package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

const lateEmptyConfig = `{"inbounds":[{"tag":"managed","settings":{"clients":[]}}]}`

func writeLateConfig(t *testing.T, p *ConfigPersister, config string) {
	t.Helper()
	if err := os.WriteFile(p.path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
}

func readLateFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func stopLateStartup(t *testing.T, s *UserStore, p *ConfigPersister) {
	t.Helper()
	if err := s.Stop(); err != nil {
		t.Errorf("store stop: %v", err)
	}
	if err := p.Stop(); err != nil {
		t.Errorf("config stop: %v", err)
	}
}

func TestStartupLateClientsProtected(t *testing.T) {
	for _, path := range []string{"flush", "persister-stop", "store-save-and-stop", "store-stop-first"} {
		t.Run(path, func(t *testing.T) {
			s, p := startupFiles(t, emptyStore, lateEmptyConfig)
			defer stopLateStartup(t, s, p)
			if s.needsFullSync() || s.GetLastSync().IsZero() {
				t.Fatal("expected a valid empty store with a historical lastSync")
			}
			writeLateConfig(t, p, populatedConfig)
			switch path {
			case "flush":
				if n := reconcileNow(t, s, p); n != 0 {
					t.Errorf("blocked flush requested %d heals", n)
				}
			case "persister-stop":
				if err := p.Stop(); err != nil {
					t.Fatal(err)
				}
			case "store-save-and-stop":
				if err := s.Save(); err != nil {
					t.Fatal(err)
				}
				if readLateFile(t, s.filePath) != emptyStore {
					t.Error("save overwrote the protected users.json")
				}
			}
			stopLateStartup(t, s, p)
			if readLateFile(t, p.path) != populatedConfig || readLateFile(t, s.filePath) != emptyStore {
				t.Fatal("late managed clients or original users.json were overwritten")
			}
		})
	}
}

func TestStartupLateClientsGuardAllManagedInboundsUntilSync(t *testing.T) {
	const empty = `{"inbounds":[{"tag":"managed","settings":{"clients":[]}},{"tag":"second","settings":{"clients":[]}}]}`
	const late = `{"inbounds":[{"tag":"managed","settings":{"clients":[]}},{"tag":"second","settings":{"clients":[{"id":"old","email":"keep"}]}}]}`
	s, p := startupFiles(t, emptyStore, empty)
	defer stopLateStartup(t, s, p)
	p.inbounds = append(p.inbounds, InboundEntry{Tag: "second"})
	if !s.Add(&User{ID: "delta", Email: "delta"}) {
		t.Fatal("delta rejected for empty startup")
	}
	writeLateConfig(t, p, late)
	if changed, err := p.Flush(); changed || err != nil {
		t.Fatalf("conflicting flush = (%v, %v), want a no-op", changed, err)
	}
	if readLateFile(t, p.path) != late || !s.needsFullSync() {
		t.Fatal("late conflict was not latched, or partially wrote another inbound")
	}

	// Commit through the same store operation used by a successful full /sync.
	lease := s.admitMutation()
	if lease == nil {
		t.Fatal("full sync not admitted")
	}
	lease.Sync([]*User{})
	lease.Done()
	if changed, err := p.Flush(); !changed || err != nil {
		t.Fatalf("authoritative flush = (%v, %v), want a rewrite", changed, err)
	}
	if strings.Contains(readLateFile(t, p.path), `"keep"`) {
		t.Fatal("full sync did not release the guard")
	}
}

func TestStartupEmptyStoreAllowsDeltasWithoutManagedConflict(t *testing.T) {
	const unmanaged = `{"inbounds":[{"tag":"other","settings":{"clients":[{"email":"unmanaged"}]}},{"tag":"managed","settings":{"clients":[]}}]}`
	for _, tc := range []struct{ name, config string }{{"empty", lateEmptyConfig}, {"unmanaged", unmanaged}} {
		t.Run(tc.name, func(t *testing.T) {
			s, p := startupFiles(t, emptyStore, lateEmptyConfig)
			defer stopLateStartup(t, s, p)
			writeLateConfig(t, p, tc.config)
			if changed, err := p.Flush(); changed || err != nil || readLateFile(t, p.path) != tc.config {
				t.Fatalf("empty startup unexpectedly rewrote config: changed=%v err=%v", changed, err)
			}
			if !s.Add(&User{ID: "delta", Email: "delta"}) {
				t.Fatal("add rejected")
			}
			if _, err := p.Flush(); err != nil {
				t.Fatal(err)
			}
			if err := s.Save(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(readLateFile(t, p.path), `"delta"`) || !strings.Contains(readLateFile(t, s.filePath), `"delta"`) {
				t.Fatal("add not persisted to both files")
			}
			if !s.Remove("delta") {
				t.Fatal("remove rejected")
			}
			stopLateStartup(t, s, p)
			config := readLateFile(t, p.path)
			if s.needsFullSync() || strings.Contains(config, `"delta"`) || strings.Contains(readLateFile(t, s.filePath), `"delta"`) {
				t.Fatal("the agent's own clients blocked a subsequent delta")
			}
			if tc.name == "unmanaged" && !strings.Contains(config, `"unmanaged"`) {
				t.Fatal("unmanaged clients were removed")
			}
		})
	}
}

func TestStartupLateClientsDuringHealGrace(t *testing.T) {
	s, p := startupFiles(t, emptyStore, lateEmptyConfig)
	defer stopLateStartup(t, s, p)
	s.Add(&User{ID: "delta", Email: "delta"})
	waits, restarts := 0, 0
	var initial string
	var writeErr error
	r := startStartupReconcile(startupReconcileDeps{
		wait: func(context.Context, time.Duration) bool {
			waits++
			if waits == 2 {
				// First flush persisted a normal delta. The panel populates the
				// managed inbound before the startup reflush, not before Load.
				data, err := os.ReadFile(p.path)
				initial, writeErr = string(data), err
				if writeErr == nil {
					writeErr = os.WriteFile(p.path, []byte(populatedConfig), 0600)
				}
			}
			return true
		},
		flush:    p.Flush,
		lastSync: s.GetLastSync,
		restart:  func(context.Context) ([]byte, error) { restarts++; return nil, nil },
		discard:  func(context.Context) error { return nil },
	})
	awaitStartupSignal(t, r.done)
	r.Stop()
	if writeErr != nil || !strings.Contains(initial, `"delta"`) {
		t.Fatalf("failed to arrange late population after initial delta flush: %v", writeErr)
	}
	if restarts != 0 || readLateFile(t, p.path) != populatedConfig {
		t.Fatal("late conflict during startup grace allowed a heal or config rewrite")
	}
}
