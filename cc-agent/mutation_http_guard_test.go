package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failOnRead struct{ t *testing.T }

func (b failOnRead) Read([]byte) (int, error) {
	b.t.Error("mutation request body was read")
	return 0, io.EOF
}
func (failOnRead) Close() error { return nil }

func loadGuardConfig(t *testing.T, contents string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestHTTPMutationGuardDeniesSyncBeforeBodyOrDependencies(t *testing.T) {
	cfg := loadGuardConfig(t, `{"token":"test-token","http_mutation_policy":"deny"}`)
	mux := http.NewServeMux()
	(&API{cfg: cfg}).RegisterRoutes(mux)
	req := httptest.NewRequest(http.MethodPost, "/sync", nil)
	req.Body = failOnRead{t}
	req.Header.Set("Authorization", "Bearer test-token")
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("POST /sync: got %d (%s), want 403", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "denied") {
		t.Fatalf("POST /sync: missing denial message: %s", res.Body.String())
	}
}

func TestHTTPMutationGuardRoutesAndAuthentication(t *testing.T) {
	cfg := loadGuardConfig(t, `{"token":"test-token","http_mutation_policy":"deny"}`)
	mux := http.NewServeMux()
	(&API{cfg: cfg}).RegisterRoutes(mux) // Nil dependencies fail if a mutation reaches its handler.
	routes := []struct{ method, path string }{
		{http.MethodPost, "/sync"},
		{http.MethodPost, "/users"},
		{http.MethodDelete, "/users/alice%40example.org"},
		{http.MethodPost, "/restart"},
	}
	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			for _, authenticated := range []bool{true, false} {
				req := httptest.NewRequest(route.method, route.path, nil)
				req.Body = failOnRead{t}
				want := http.StatusUnauthorized
				if authenticated {
					req.Header.Set("Authorization", "Bearer test-token")
					want = http.StatusForbidden
				}
				res := httptest.NewRecorder()
				mux.ServeHTTP(res, req)
				if res.Code != want {
					t.Fatalf("authenticated=%v: got %d (%s), want %d", authenticated, res.Code, res.Body.String(), want)
				}
				if authenticated {
					var body map[string]string
					if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil || !strings.Contains(body["error"], "denied") {
						t.Fatalf("missing machine-readable denial: %s (%v)", res.Body.String(), err)
					}
				}
			}
		})
	}
}

func TestHTTPMutationGuardKeepsReadOnlyRoutes(t *testing.T) {
	cfg := loadGuardConfig(t, `{"token":"test-token","http_mutation_policy":"deny"}`)
	cfg.DataDir = t.TempDir()
	mux := http.NewServeMux()
	(&API{cfg: cfg, userStore: NewUserStore(cfg)}).RegisterRoutes(mux)
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/health"},
		{http.MethodGet, "/info"},
		{http.MethodPost, "/connect"},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req := httptest.NewRequest(route.method, route.path, nil)
			req.Header.Set("Authorization", "Bearer test-token")
			res := httptest.NewRecorder()
			mux.ServeHTTP(res, req)
			if res.Code != http.StatusOK {
				t.Fatalf("%s %s: got %d (%s), want 200", route.method, route.path, res.Code, res.Body.String())
			}
			if route.path == "/health" && !strings.Contains(res.Body.String(), `"status":"ok"`) {
				t.Fatalf("health not OK: %s", res.Body.String())
			}
			if route.path == "/info" && !strings.Contains(res.Body.String(), `"agent_version"`) {
				t.Fatalf("info missing version: %s", res.Body.String())
			}
		})
	}
}

func TestHTTPMutationPolicyDefaultPreservesHandlers(t *testing.T) {
	cfg := loadGuardConfig(t, `{"token":"test-token"}`)
	if cfg.HTTPMutationPolicy != "" {
		t.Fatalf("absent policy should be unset, got %q", cfg.HTTPMutationPolicy)
	}
	mux := http.NewServeMux()
	(&API{cfg: cfg}).RegisterRoutes(mux)
	for _, path := range []string{"/sync", "/users"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("invalid json"))
		req.Header.Set("Authorization", "Bearer test-token")
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("POST %s without policy: got %d (%s), want existing handler's 400", path, res.Code, res.Body.String())
		}
	}
}

func TestHTTPMutationPolicyRejectsMalformedPresentValues(t *testing.T) {
	for _, value := range []string{`null`, `""`, `"allow"`, `"DENY"`, `true`, `false`, `1`, `{}`} {
		t.Run(value, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(`{"http_mutation_policy":`+value+`}`), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatalf("present policy %s must fail config load", value)
			}
		})
	}
}
