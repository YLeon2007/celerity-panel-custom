package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const populatedConfig = `{"inbounds":[{"tag":"other","settings":{"clients":[{"email":"unmanaged"}]}},{"tag":"managed","settings":{"clients":[{"id":"old","email":"keep"}]}}]}`
const emptyStore = `{"users":[],"lastSync":"2026-01-01T00:00:00Z"}`

func startupFiles(t *testing.T, storeText, config string) (*UserStore, *ConfigPersister) {
	t.Helper()
	dir := t.TempDir()
	cfg := &Config{DataDir: dir, Inbounds: []InboundEntry{{Tag: "managed"}}}
	s := NewUserStore(cfg)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	if storeText == "READ_ERROR" {
		if err := os.Mkdir(s.filePath, 0700); err != nil {
			t.Fatal(err)
		}
	} else if storeText != "MISSING" {
		if err := os.WriteFile(s.filePath, []byte(storeText), 0600); err != nil {
			t.Fatal(err)
		}
	}
	p := NewConfigPersister(path, cfg.Inbounds, s)
	_ = s.Load(p.checkEmptyStore)
	go p.run()
	return s, p
}

func reconcileNow(t *testing.T, s *UserStore, p *ConfigPersister) int {
	t.Helper()
	restarts := 0
	r := startStartupReconcile(startupReconcileDeps{
		wait:  func(context.Context, time.Duration) bool { return true },
		flush: p.Flush, lastSync: s.GetLastSync,
		restart: func(context.Context) ([]byte, error) { restarts++; return nil, nil },
		discard: func(context.Context) error { return nil },
	})
	awaitStartupSignal(t, r.done)
	r.Stop()
	return restarts
}

func TestStartupStorePreservesStateUntilSync(t *testing.T) {
	for _, tc := range []struct{ name, store string }{{"truncated", `{"users":`}, {"zero-bytes", ""}, {"read-error", "READ_ERROR"}, {"missing", "MISSING"}, {"empty", emptyStore}} {
		t.Run(tc.name, func(t *testing.T) {
			s, p := startupFiles(t, tc.store, populatedConfig)
			write := p.writeFile
			p.writeFile = func(path string, data []byte) error {
				t.Error("unexpected config write before sync")
				return write(path, data)
			}
			if n := reconcileNow(t, s, p); n != 0 {
				t.Errorf("startup requested %d restarts before sync", n)
			}
			p.MarkDirty()
			if err := s.Save(); err != nil {
				t.Error(err)
			}
			if err := s.Stop(); err != nil {
				t.Errorf("store stop: %v", err)
			}
			if err := p.Stop(); err != nil {
				t.Errorf("config stop: %v", err)
			}
			got, err := os.ReadFile(p.path)
			if err != nil || string(got) != populatedConfig {
				t.Error("protected config changed")
			}
			if tc.store == "READ_ERROR" {
				return
			}
			got, err = os.ReadFile(s.filePath)
			if tc.store == "MISSING" {
				if !os.IsNotExist(err) {
					t.Error("absent store created")
				}
			} else if err != nil || string(got) != tc.store {
				t.Error("untrusted store overwritten")
			}
		})
	}
}
func TestStartupStoreValidStillHeals(t *testing.T) {
	s, p := startupFiles(t, `{"users":[{"id":"new","email":"current"}]}`, populatedConfig)
	defer s.Stop()
	defer p.Stop()
	if n := reconcileNow(t, s, p); n != 1 {
		t.Fatalf("want original single heal, got %d", n)
	}
	b, err := os.ReadFile(p.path)
	if err != nil || !strings.Contains(string(b), `"current"`) || !strings.Contains(string(b), `"unmanaged"`) {
		t.Fatal("managed clients not reconciled or unmanaged inbound lost")
	}
}
func TestStartupStoreRecoversOnlyOnFullSync(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // Never run systemctl, even on a regression.
	s, p := startupFiles(t, `{`, populatedConfig)
	defer p.Stop()
	defer s.Stop()
	api, _ := recoveryTestAPI(s, p)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	send := func(path, body string) int {
		req := httptest.NewRequest("POST", path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer fixture")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w.Code
	}
	for _, x := range []struct{ path, body string }{{"/sync", `{}`}, {"/sync", `{"users":null}`}} {
		if got := send(x.path, x.body); got != 400 {
			t.Fatalf("invalid snapshot accepted: HTTP %d", got)
		}
	}
	if got := send("/restart", ``); got != 503 {
		t.Fatalf("restart not refused: %d", got)
	}
	if got := send("/users", `{"id":"one","email":"one"}`); got != 503 {
		t.Fatalf("delta not refused: %d", got)
	}
	if got := send("/sync", `{"users":[]}`); got != 200 {
		t.Fatalf("explicit empty sync rejected: %d", got)
	}
	if _, err := p.Flush(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p.path)
	if err != nil || strings.Contains(string(b), `"keep"`) || !strings.Contains(string(b), `"unmanaged"`) {
		t.Fatal("authoritative empty sync not applied to managed inbound only")
	}
}

func TestRestartDetectsLateManagedClients(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	s, p := startupFiles(t, emptyStore, lateEmptyConfig)
	defer stopLateStartup(t, s, p)
	writeLateConfig(t, p, populatedConfig)
	w := httptest.NewRecorder()
	(&API{userStore: s, persister: p}).handleRestart(w, httptest.NewRequest(http.MethodPost, "/restart", nil))
	if w.Code != http.StatusServiceUnavailable || readLateFile(t, p.path) != populatedConfig {
		t.Fatal("restart did not preserve the newly populated config")
	}
}

func TestStartupStoreSaveAtomic(t *testing.T) {
	s := NewUserStore(&Config{DataDir: t.TempDir()})
	s.Add(&User{ID: "one", Email: "one"})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	alias := s.filePath + ".old"
	if err := os.Link(s.filePath, alias); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(alias)
	if err != nil {
		t.Fatal(err)
	}
	s.Add(&User{ID: "two", Email: "two"})
	if err = s.Save(); err != nil {
		t.Fatal(err)
	}
	old, err := os.ReadFile(alias)
	if err != nil || string(old) != string(before) {
		t.Fatal("previous inode truncated/overwritten")
	}
	st, err := os.Stat(s.filePath)
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("users snapshot must be private")
	}
	b, err := os.ReadFile(s.filePath)
	var pd persistedData
	if err != nil || json.Unmarshal(b, &pd) != nil || len(pd.Users) != 2 {
		t.Fatal("new snapshot incomplete")
	}
}
