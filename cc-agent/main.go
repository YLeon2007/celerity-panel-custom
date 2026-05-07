package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const Version = "1.2.0"

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

	// Restore users to Xray after a brief startup delay (Xray might still be starting),
	// then discard the first Xray stats snapshot. Xray accumulates counters from boot,
	// and without this discard the panel's first /stats poll would attribute all of
	// that since-boot traffic to the current interval, producing a cold-start spike.
	go func() {
		time.Sleep(3 * time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		count, err := userStore.RestoreToXray(ctx, xrayClient)
		if err != nil {
			log.Printf("[main] Warning: RestoreToXray: %v", err)
		} else {
			log.Printf("[main] Restored %d users to Xray", count)
		}
		if _, err := xrayClient.QueryStats(ctx, "", true); err != nil {
			log.Printf("[main] Startup stats discard failed: %v", err)
		} else {
			log.Printf("[main] Startup stats discarded (cold-start reset)")
		}
	}()

	// Periodic user store flush to disk every 5 minutes
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			if err := userStore.Save(); err != nil {
				log.Printf("[store] Save error: %v", err)
			}
		}
	}()

	api := &API{
		cfg:        cfg,
		userStore:  userStore,
		xrayClient: xrayClient,
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)

	_ = userStore.Save()
	log.Printf("[main] Shutdown complete")
}
