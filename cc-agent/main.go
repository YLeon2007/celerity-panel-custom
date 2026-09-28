package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

const Version = "1.4.0"

var startTime = time.Now()

func main() {
	configPath := flag.String("config", "/etc/cc-agent/config.json", "Path to config file")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		log.Printf("cc-agent %s", Version)
		os.Exit(0)
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("[main] Failed to load config: %v", err)
	}

	userStore := NewUserStore(cfg)
	if err := userStore.Load(); err != nil {
		log.Printf("[main] Warning: could not load users from disk: %v", err)
	}

	xrayClient, err := NewXrayClient(cfg)
	if err != nil {
		log.Printf("[main] Warning: could not connect to Xray gRPC: %v (will retry on use)", err)
	}

	// ConfigPersister keeps /usr/local/etc/xray/config.json in sync with the
	// authoritative user list so any Xray restart reloads the correct users.
	persister := NewConfigPersister(xrayConfigPath, cfg.Inbounds, userStore)
	go persister.run()

	onlineTracker := NewOnlineTracker(defaultOnlineTimeout)
	watchCtx, stopOnlineWatcher := context.WithCancel(context.Background())
	defer stopOnlineWatcher()
	go onlineTracker.RunJournalWatcher(watchCtx)

	// Startup reconciliation. Make the on-disk config reflect the current users
	// (durability), then heal the running Xray only if the disk was actually
	// stale and no panel /sync arrived to fix the runtime during the grace window.
	// A panel full-push restarts cc-agent (reloadCcAgent) BEFORE it calls /sync,
	// so the grace window avoids a redundant heal restart in that race.
	startup := startStartupReconcile(startupReconcileDeps{
		wait:     waitStartup,
		flush:    persister.Flush,
		lastSync: userStore.GetLastSync,
		restart:  restartXrayForStartup,
		discard: func(ctx context.Context) error {
			_, err := xrayClient.QueryStats(ctx, "", true)
			return err
		},
	})

	// Periodic user store flush; cancel and join this loop before store Stop.
	storeTicker := time.NewTicker(5 * time.Minute)
	stopStoreSaves := make(chan struct{})
	storeSaverDone := make(chan struct{})
	go func() {
		defer close(storeSaverDone)
		runPeriodicUserSaves(stopStoreSaves, storeTicker.C, userStore)
	}()

	// Optional access-log shipping module. It remains inert unless explicitly enabled.
	var shipper *Shipper
	if cfg.AccessLogs.Enabled && cfg.AccessLogs.IngestURL != "" && cfg.AccessLogs.IngestToken != "" {
		shipper = NewShipper(cfg)
		shipper.Start()
	}

	api := &API{
		cfg:           cfg,
		userStore:     userStore,
		xrayClient:    xrayClient,
		persister:     persister,
		onlineTracker: onlineTracker,
		shipper:       shipper,
	}

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	server := &http.Server{
		Addr:         cfg.Listen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if cfg.TLS.Enabled {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
		if err != nil {
			log.Fatalf("[main] TLS cert load error: %v", err)
		}
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		log.Printf("[main] CC Agent %s starting on %s (TLS: %v)", Version, cfg.Listen, cfg.TLS.Enabled)
		var srvErr error
		if cfg.TLS.Enabled {
			srvErr = server.ListenAndServeTLS("", "")
		} else {
			srvErr = server.ListenAndServe()
		}
		if srvErr != nil && srvErr != http.ErrServerClosed {
			log.Fatalf("[main] Server error: %v", srvErr)
		}
	}()

	<-sigCh
	log.Printf("[main] Shutting down...")
	// Cancel before HTTP shutdown's grace period; join before stopping stores.
	startup.Cancel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[main] HTTP shutdown: %v; store Stop will drain admitted user mutations", err)
	}
	startup.Stop()

	if shipper != nil {
		shipper.Stop()
	}
	storeTicker.Stop()
	close(stopStoreSaves)
	<-storeSaverDone

	// Close user mutation admission before the config persister's final
	// snapshot, so both files reflect the same accepted user state.
	if err := userStore.Stop(); err != nil {
		log.Printf("[store] Final save: %v", err)
	}
	if err := persister.Stop(); err != nil {
		log.Printf("[config] Final flush: %v", err)
	}
	log.Printf("[main] Shutdown complete")
}

type startupReconcileDeps struct {
	wait     func(context.Context, time.Duration) bool
	flush    func() (bool, error)
	lastSync func() time.Time
	restart  func(context.Context) ([]byte, error)
	discard  func(context.Context) error
}

type startupReconciler struct {
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	gate   sync.Mutex // fences admission of local side effects against Stop
}

func startStartupReconcile(deps startupReconcileDeps) *startupReconciler {
	ctx, cancel := context.WithCancel(context.Background())
	r := &startupReconciler{ctx: ctx, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		r.run(deps)
	}()
	return r
}

func (r *startupReconciler) Cancel() { r.cancel() }

func (r *startupReconciler) Stop() {
	r.Cancel()
	r.gate.Lock()
	r.gate.Unlock()
	<-r.done
}

func waitStartup(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}

// invoke only admits work while running. Stop cancels first, then joins the
// gate and the worker. A call already admitted may finish after cancellation;
// joining it does not prove that a systemd restart job has completed on host.
func (r *startupReconciler) invoke(fn func()) bool {
	r.gate.Lock()
	defer r.gate.Unlock()
	if r.ctx.Err() != nil {
		return false
	}
	fn()
	return true
}

func (r *startupReconciler) run(d startupReconcileDeps) {
	if !d.wait(r.ctx, 3*time.Second) || r.ctx.Err() != nil {
		return
	}
	// The initial flush, not the reflush, determines whether runtime is stale.
	var diskWasStale bool
	if !r.invoke(func() {
		var err error
		diskWasStale, err = d.flush()
		if err != nil {
			log.Printf("[main] Startup config flush: %v", err)
		}
	}) {
		return
	}
	if r.ctx.Err() != nil {
		return
	}
	syncBefore := d.lastSync()
	if !d.wait(r.ctx, 15*time.Second) || r.ctx.Err() != nil {
		return
	}
	syncedDuringGrace := !d.lastSync().Equal(syncBefore)
	// The reflush captures grace-window changes but never decides the heal.
	if !r.invoke(func() {
		if _, err := d.flush(); err != nil {
			log.Printf("[main] Startup config reflush: %v", err)
		}
	}) {
		return
	}
	if diskWasStale && !syncedDuringGrace {
		var restartOK bool
		if !r.invoke(func() {
			log.Printf("[main] Stale Xray config on startup, restarting xray once to heal runtime")
			out, err := d.restart(r.ctx)
			if err != nil {
				log.Printf("[main] Xray heal restart failed: %v, output: %s", err, out)
			} else {
				restartOK = true
			}
		}) {
			return
		}
		if restartOK && !d.wait(r.ctx, 2*time.Second) {
			return
		}
	}
	// Discard accumulated boot counters before the panel's first stats poll.
	r.invoke(func() {
		ctx, cancel := context.WithTimeout(r.ctx, 60*time.Second)
		defer cancel()
		if err := d.discard(ctx); err != nil {
			log.Printf("[main] Startup stats discard failed: %v", err)
		} else {
			log.Printf("[main] Startup stats discarded (cold-start reset)")
		}
	})
}

func restartXrayForStartup(ctx context.Context) ([]byte, error) {
	// CommandContext bounds the local client process on shutdown. systemd may
	// already have queued a job; its exit is NOT a host-quiescence acknowledgement.
	cmd := exec.CommandContext(ctx, "systemctl", "restart", "xray")
	cmd.WaitDelay = time.Second // bound waits on inherited stdout/stderr pipes
	return cmd.CombinedOutput()
}

func runPeriodicUserSaves(stop <-chan struct{}, ticks <-chan time.Time, store *UserStore) {
	for {
		select {
		case <-stop:
			return
		case <-ticks:
			// If cancellation raced with a tick, do not start another write.
			select {
			case <-stop:
				return
			default:
			}
			if err := store.Save(); err != nil {
				log.Printf("[store] Save error: %v", err)
			}
		}
	}
}
