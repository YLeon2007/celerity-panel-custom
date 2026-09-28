package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	proxyman_command "github.com/xtls/xray-core/app/proxyman/command"
	"google.golang.org/grpc"
)

type blockingAlterInbound struct {
	proxyman_command.HandlerServiceClient
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (b *blockingAlterInbound) AlterInbound(ctx context.Context, _ *proxyman_command.AlterInboundRequest, _ ...grpc.CallOption) (*proxyman_command.AlterInboundResponse, error) {
	if b.calls.Add(1) == 1 {
		close(b.entered)
		select {
		case <-b.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &proxyman_command.AlterInboundResponse{}, nil
}

// Stop must fence new HTTP requests, but complete an admitted request's RPC,
// store update, and dirty notification before its final snapshots.
func TestStopDrainsHTTPXrayMutations(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		initial, final           bool
	}{
		{"add", http.MethodPost, "/users", `{"id":"id-1","email":"a@example.org"}`, false, true},
		{"remove", http.MethodDelete, "/users/a@example.org", "", true, false},
		{"sync-add", http.MethodPost, "/sync", `{"users":[{"id":"id-1","email":"a@example.org"}]}`, false, true},
		{"sync-remove", http.MethodPost, "/sync", `{"users":[]}`, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := &Config{DataDir: dir, Token: "test-token"}
			store := NewUserStore(cfg)
			if tc.initial && !store.Add(&User{ID: "id-1", Email: "a@example.org"}) {
				t.Fatal("initial user rejected")
			}
			configPath := filepath.Join(dir, "config.json")
			clients := `[]`
			if tc.initial {
				clients = `[{"id":"id-1","email":"a@example.org","level":0}]`
			}
			if err := os.WriteFile(configPath, []byte(`{"inbounds":[{"tag":"test","settings":{"clients":`+clients+`}}]}`), 0600); err != nil {
				t.Fatal(err)
			}
			persister := NewConfigPersister(configPath, []InboundEntry{{Tag: "test"}}, store)
			go persister.run()
			rpc := &blockingAlterInbound{entered: make(chan struct{}), release: make(chan struct{})}
			api := &API{cfg: cfg, userStore: store, persister: persister, xrayClient: &XrayClient{proxyman: rpc, inbounds: []InboundEntry{{Tag: "test"}}}}
			mux := http.NewServeMux()
			api.RegisterRoutes(mux)
			request := func() *http.Request {
				req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
				req.Header.Set("Authorization", "Bearer test-token")
				return req
			}
			response := make(chan *httptest.ResponseRecorder, 1)
			go func() { w := httptest.NewRecorder(); mux.ServeHTTP(w, request()); response <- w }()
			select {
			case <-rpc.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("RPC not entered")
			}
			stopped := make(chan error, 1)
			go func() { stopped <- store.Stop() }()
			deadline := time.Now().Add(3 * time.Second)
			for store.acceptingMutations() && time.Now().Before(deadline) {
				runtime.Gosched()
			}
			if store.acceptingMutations() {
				t.Fatal("Stop did not fence mutation admission")
			}
			select {
			case err := <-stopped:
				t.Fatalf("Stop returned before admitted RPC completed: %v", err)
			default:
			}
			late := httptest.NewRecorder()
			mux.ServeHTTP(late, request())
			if late.Code != http.StatusServiceUnavailable {
				t.Fatalf("late status = %d (%s), want 503", late.Code, late.Body.String())
			}
			if n := rpc.calls.Load(); n != 1 {
				t.Fatalf("late request reached Xray: calls=%d", n)
			}
			close(rpc.release)
			select {
			case w := <-response:
				if w.Code != http.StatusOK {
					t.Fatalf("admitted status = %d (%s), want 200", w.Code, w.Body.String())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("admitted HTTP handler stuck")
			}
			if err := awaitStore(t, stopped); err != nil {
				t.Fatal(err)
			}
			if err := persister.Stop(); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(store.filePath)
			if err != nil {
				t.Fatal(err)
			}
			var persisted persistedData
			if err := json.Unmarshal(raw, &persisted); err != nil {
				t.Fatal(err)
			}
			raw, err = os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Inbounds []struct {
					Settings struct {
						Clients []User `json:"clients"`
					} `json:"settings"`
				} `json:"inbounds"`
			}
			if err := json.Unmarshal(raw, &config); err != nil {
				t.Fatal(err)
			}
			want := 0
			if tc.final {
				want = 1
			}
			if len(persisted.Users) != want || len(config.Inbounds) != 1 || len(config.Inbounds[0].Settings.Clients) != want {
				t.Fatalf("final snapshots: users=%+v config=%s, want %d users", persisted.Users, raw, want)
			}
			if tc.final && (persisted.Users[0].Email != "a@example.org" || persisted.Users[0].ID != "id-1" ||
				config.Inbounds[0].Settings.Clients[0].Email != "a@example.org" || config.Inbounds[0].Settings.Clients[0].ID != "id-1") {
				t.Fatalf("final snapshots contain wrong user: users=%+v config=%s", persisted.Users, raw)
			}
		})
	}
}
