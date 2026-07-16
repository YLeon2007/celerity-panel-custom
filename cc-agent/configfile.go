package main

import (
	"encoding/json"
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

	mu       sync.Mutex
	dirty    chan struct{}
	done     chan struct{}
	debounce time.Duration
}

func NewConfigPersister(path string, inbounds []InboundEntry, store *UserStore) *ConfigPersister {
	return &ConfigPersister{
		path:     path,
		inbounds: inbounds,
		store:    store,
		dirty:    make(chan struct{}, 1),
		done:     make(chan struct{}),
		debounce: 1 * time.Second,
	}
}

// MarkDirty schedules a debounced flush. Non-blocking and safe to call from any
// request handler; bursts coalesce into a single write.
func (p *ConfigPersister) MarkDirty() {
	select {
	case p.dirty <- struct{}{}:
	default:
	}
}

// run is the debounce loop: it flushes the config ~debounce after the last
// change, bounding writes to at most one per debounce interval regardless of
// churn. Stop() ends the loop.
func (p *ConfigPersister) run() {
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

// Stop terminates the debounce loop. Callers should perform a final synchronous
// Flush afterwards to capture any pending change.
func (p *ConfigPersister) Stop() {
	close(p.done)
}

// Flush reads the on-disk config, replaces the clients of every managed inbound
// with the current user list, and atomically writes the file back. It returns
// changed=true only when the managed client sets actually differed (so callers
// can decide whether a one-shot xray restart is warranted). A missing config or
// missing inbounds array is treated as a no-op (not an error).
func (p *ConfigPersister) Flush() (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	data, err := os.ReadFile(p.path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("read %s: %w", p.path, err)
	}

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		// A hand-edited config with comments/trailing commas lands here. Keep the
		// existing file untouched; the live gRPC state is unaffected.
		return false, fmt.Errorf("parse %s: %w", p.path, err)
	}

	inboundsAny, ok := root["inbounds"].([]any)
	if !ok {
		return false, nil
	}

	managed := make(map[string]InboundEntry, len(p.inbounds))
	for _, ib := range p.inbounds {
		managed[ib.Tag] = ib
	}

	users := p.store.List()

	changed := false
	for _, ibAny := range inboundsAny {
		ib, ok := ibAny.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := ib["tag"].(string)
		entry, isManaged := managed[tag]
		if !isManaged {
			continue
		}

		desired := buildConfigUsers(users, entry)

		settings, ok := ib["settings"].(map[string]any)
		if !ok {
			settings = map[string]any{}
			ib["settings"] = settings
		}
		// Both VLESS and native Hysteria use settings.clients in Xray JSON;
		// buildConfigUsers selects the protocol-specific credential key.
		field := "clients"
		existing, _ := settings[field].([]any)
		if usersEqual(existing, desired) {
			continue
		}
		settings[field] = desired
		changed = true
	}

	if !changed {
		return false, nil
	}

	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal %s: %w", p.path, err)
	}

	if err := atomicWriteFile(p.path, out); err != nil {
		return false, err
	}
	log.Printf("[config] Rewrote %s (%d users)", p.path, len(users))
	return true, nil
}

// buildConfigUsers renders the protocol-specific user array stored in
// config.json. VLESS uses settings.clients[].id; native Hysteria uses
// settings.clients[].auth. The panel user UUID is valid for both.
func buildConfigUsers(users []*User, inbound InboundEntry) []any {
	items := make([]any, 0, len(users))
	for _, u := range users {
		item := map[string]any{
			"email": u.Email,
			"level": 0,
		}
		if inbound.Protocol == "hysteria" {
			item["auth"] = u.ID
		} else {
			item["id"] = u.ID
			if inbound.Flow != "" {
				item["flow"] = inbound.Flow
			}
		}
		items = append(items, item)
	}
	return items
}

// usersEqual compares VLESS/Hysteria user arrays as sets, ignoring order and
// the always-zero level. It supports both id and auth credential keys.
func usersEqual(existing, desired []any) bool {
	if len(existing) != len(desired) {
		return false
	}
	set := make(map[string]struct{}, len(existing))
	for _, c := range existing {
		m, ok := c.(map[string]any)
		if !ok {
			return false
		}
		set[userKey(m)] = struct{}{}
	}
	for _, c := range desired {
		m, ok := c.(map[string]any)
		if !ok {
			return false
		}
		if _, ok := set[userKey(m)]; !ok {
			return false
		}
	}
	return true
}

func userKey(m map[string]any) string {
	id, _ := m["id"].(string)
	auth, _ := m["auth"].(string)
	email, _ := m["email"].(string)
	flow, _ := m["flow"].(string)
	return id + "\x00" + auth + "\x00" + email + "\x00" + flow
}

// atomicWriteFile writes data to a temp file in the same directory, fsyncs it,
// then renames it over the target so a crash/power loss never leaves a partial
// config.json.
func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".xray-config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed away

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Chmod(tmpName, 0644); err != nil {
		return fmt.Errorf("chmod temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp -> %s: %w", path, err)
	}
	return nil
}
