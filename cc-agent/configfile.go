package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ConfigPersister keeps the on-disk Xray config.json in sync with the agent's
// authoritative user list (UserStore). Live user changes are applied to the
// running Xray over gRPC; this persister mirrors them into config.json so that
// any Xray restart (systemd/crash/OOM) reloads the correct user set instead of
// a stale snapshot. It only ever rewrites the settings.clients arrays of the
// inbounds the agent manages (cfg.Inbounds); every other part of the config
// (routing, outbounds, tls, stream, cascade inbounds) is preserved verbatim.
type ConfigPersister struct {
	path     string
	inbounds []InboundEntry
	store    *UserStore

	mu        sync.Mutex
	dirty     chan struct{}
	done      chan struct{}
	loopDone  chan struct{}
	stopOnce  sync.Once
	stopped   bool
	stopErr   error
	debounce  time.Duration
	writeFile func(string, []byte) error // test seam at the real atomic write boundary

	// Managed clients last published by this process before its first /sync.
	// Guarded by store.startupMu, including checks from the user-file save path.
	startupClients map[string]map[configClientKey]struct{}
}

func NewConfigPersister(path string, inbounds []InboundEntry, store *UserStore) *ConfigPersister {
	return &ConfigPersister{
		path:      path,
		inbounds:  inbounds,
		store:     store,
		dirty:     make(chan struct{}, 1),
		done:      make(chan struct{}),
		loopDone:  make(chan struct{}),
		debounce:  1 * time.Second,
		writeFile: atomicWriteFile,
	}
}

// MarkDirty schedules a debounced flush. Non-blocking and safe to call from any
// request handler; bursts coalesce into a single write.
func (p *ConfigPersister) MarkDirty() {
	select {
	case <-p.done:
		return
	default:
	}
	select {
	case p.dirty <- struct{}{}:
	default:
	}
}

// run is the debounce loop: it flushes the config ~debounce after the last
// change, bounding writes to at most one per debounce interval regardless of
// churn. Stop() ends the loop.
func (p *ConfigPersister) run() {
	defer close(p.loopDone)
	var timer *time.Timer
	var timerC <-chan time.Time
	for {
		select {
		case <-p.done:
			if timer != nil {
				timer.Stop()
			}
			return
		case <-p.dirty:
			if timer == nil {
				timer = time.NewTimer(p.debounce)
				timerC = timer.C
			} else {
				timer.Stop()
				timer.Reset(p.debounce)
			}
		case <-timerC:
			timer = nil
			timerC = nil
			if _, err := p.Flush(); err != nil {
				log.Printf("[config] Flush failed: %v", err)
			}
		}
	}
}

// Stop closes admission, waits for the debounce loop and any in-flight Flush,
// then flushes the latest user snapshot before acknowledging. It is idempotent.
// All Flush calls after Stop are rejected; callers must not attempt a final Flush.
func (p *ConfigPersister) Stop() error {
	p.stopOnce.Do(func() {
		p.mu.Lock()
		p.stopped = true
		close(p.done)
		p.mu.Unlock()
		<-p.loopDone
		p.mu.Lock()
		_, p.stopErr = p.flushLocked()
		p.mu.Unlock()
	})
	return p.stopErr
}

var errPersisterStopped = errors.New("config persister stopped")

// Flush reads the on-disk config, replaces the clients of every managed inbound
// with the current user list, and atomically writes the file back. It returns
// changed=true only for a rewrite eligible for startup heal. Writes in the
// empty-startup window only mirror deltas already applied to Xray; they must
// not arm a heal that could run after a later reflush is blocked. A missing
// config is treated as a no-op.
func (p *ConfigPersister) Flush() (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped {
		return false, errPersisterStopped
	}
	return p.flushLocked()
}

var errStartupConfigClients = errors.New("empty startup store conflicts with managed inbound clients")

// Called by Load and by user-file saves with store.startupMu held.
func (p *ConfigPersister) checkEmptyStore() error {
	data, err := os.ReadFile(p.path)
	if err != nil {
		return err
	}
	return p.checkStartupClients(data, p.managedFlows())
}

func (p *ConfigPersister) managedFlows() map[string]string {
	managed := make(map[string]string, len(p.inbounds))
	for _, ib := range p.inbounds {
		managed[ib.Tag] = ib.Flow
	}
	return managed
}

// Scan all managed inbounds in the snapshot being written. Clients from our
// own earlier delta flushes are not evidence of late external population.
func (p *ConfigPersister) checkStartupClients(data []byte, managed map[string]string) error {
	var cfg struct {
		Inbounds []struct {
			Tag      string
			Settings json.RawMessage
		}
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse %s: %w", p.path, err)
	}
	if cfg.Inbounds == nil {
		return errors.New("missing inbounds in Xray config")
	}
	for _, ib := range cfg.Inbounds {
		tag := ib.Tag
		if _, ok := managed[tag]; !ok {
			continue
		}
		var settings struct{ Clients []any }
		if err := json.Unmarshal(ib.Settings, &settings); err != nil {
			return fmt.Errorf("read clients for managed inbound %q: %w", tag, err)
		}
		clients := settings.Clients
		known := p.startupClients[tag]
		if len(clients) > len(known) {
			return errStartupConfigClients
		}
		seen := make(map[configClientKey]struct{}, len(clients))
		for _, client := range clients {
			c, ok := client.(map[string]any)
			key := clientKey(c)
			_, owned := known[key]
			_, duplicate := seen[key]
			if !ok || !owned || duplicate {
				return errStartupConfigClients
			}
			seen[key] = struct{}{}
		}
	}
	return nil
}

// flushLocked is also used by Stop for its final write after admission closes.
func (p *ConfigPersister) flushLocked() (bool, error) {
	snapshot, ok, check, done := p.store.persistenceSnapshot()
	defer done()
	if !ok {
		return false, nil
	}
	guarded := check != nil
	data, err := os.ReadFile(p.path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read %s: %w", p.path, err)
	}
	managed := p.managedFlows()
	if guarded {
		if err := p.checkStartupClients(data, managed); err != nil {
			return false, p.store.checkStartupConflict(err)
		}
	}
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		// A hand-edited config with comments/trailing commas lands here. Keep the
		// existing file untouched; the live gRPC state is unaffected.
		return false, fmt.Errorf("parse %s: %w", p.path, err)
	}
	inbounds, ok := root["inbounds"].([]any)
	if !ok {
		return false, nil
	}
	users := snapshot.Users
	var nextClients map[string]map[configClientKey]struct{}
	if guarded {
		nextClients = make(map[string]map[configClientKey]struct{}, len(managed))
	}
	changed := false
	for _, ibAny := range inbounds {
		ib, ok := ibAny.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := ib["tag"].(string)
		flow, isManaged := managed[tag]
		if !isManaged {
			continue
		}

		desired := buildConfigClients(users, flow)
		if guarded {
			keys := make(map[configClientKey]struct{}, len(users))
			for _, u := range users {
				keys[configClientKey{u.ID, u.Email, flow}] = struct{}{}
			}
			nextClients[tag] = keys
		}

		settings, ok := ib["settings"].(map[string]any)
		if !ok {
			settings = map[string]any{}
			ib["settings"] = settings
		}
		existing, _ := settings["clients"].([]any)
		if clientsEqual(existing, desired) {
			continue
		}
		settings["clients"] = desired
		changed = true
	}

	if !changed {
		return false, nil
	}

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal %s: %w", p.path, err)
	}

	if err := p.writeFile(p.path, out); err != nil {
		return false, err
	}
	if guarded {
		p.startupClients = nextClients
	}
	log.Printf("[config] Rewrote %s (%d users)", p.path, len(users))
	return !guarded, nil
}

// buildConfigClients renders the VLESS clients array. Flow is added only when
// non-empty, matching the panel's configGenerator.buildXrayClients output and
// the gRPC AddUser path (which sends per-inbound flow).
func buildConfigClients(users []*User, flow string) []any {
	clients := make([]any, 0, len(users))
	for _, u := range users {
		c := map[string]any{
			"id":    u.ID,
			"email": u.Email,
			"level": 0,
		}
		if flow != "" {
			c["flow"] = flow
		}
		clients = append(clients, c)
	}
	return clients
}

// clientsEqual compares two clients arrays as sets of (id, email, flow),
// ignoring order and the always-zero level. This avoids false "changed"
// verdicts from JSON number typing (float64) or key ordering.
func clientsEqual(existing, desired []any) bool {
	if len(existing) != len(desired) {
		return false
	}
	set := make(map[configClientKey]struct{}, len(existing))
	for _, c := range existing {
		m, ok := c.(map[string]any)
		if !ok {
			return false
		}
		set[clientKey(m)] = struct{}{}
	}
	for _, c := range desired {
		m, ok := c.(map[string]any)
		if !ok {
			return false
		}
		if _, ok := set[clientKey(m)]; !ok {
			return false
		}
	}
	return true
}

type configClientKey struct{ id, email, flow string }

func clientKey(m map[string]any) configClientKey {
	id, _ := m["id"].(string)
	email, _ := m["email"].(string)
	flow, _ := m["flow"].(string)
	return configClientKey{id, email, flow}
}

// atomicWriteFile writes data to a temp file in the same directory, fsyncs it,
// then renames it over the target so a crash/power loss never leaves a partial
// config.json.
func atomicWriteFile(path string, data []byte) error {
	return atomicWriteMode(path, data, 0644)
}

func atomicWriteMode(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed away

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp -> %s: %w", path, err)
	}
	parent, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
