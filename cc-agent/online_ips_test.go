package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	stats "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Exercise the real gRPC client and mounted HTTP/auth path; only Xray's
// response and status transitions are controlled in this fixture.
func TestOnlineIPsHTTP(t *testing.T) {
	const (
		alice = "user>>>Alice@fixture.test>>>online"
		bob   = "user>>>user-id>>>online"
		ts    = 1704067201
	)
	reverse := "user>>>" + (reverseObservationSubject{linkID: observationFixtureID, identity: strings.Repeat("a", 64)}).email() + ">>>online"
	reverseList := &stats.GetStatsOnlineIpListResponse{Name: reverse, Ips: map[string]int64{"192.0.2.77": ts}}
	for _, tc := range []struct {
		name       string
		census     []string
		censusCode codes.Code
		lists      map[string]*stats.GetStatsOnlineIpListResponse
		listCodes  map[string]codes.Code
		wantCode   int
		supported  bool
		wantUsers  map[string][]testOnlineIP
		wantLists  []string
	}{
		{
			name:   "multi-IP IPv4 and IPv6; keys deduplicated and not case-folded",
			census: []string{alice, alice, bob, "", "inbound>>>bad>>>online", "user>>>>>>online", reverse, reverse},
			lists: map[string]*stats.GetStatsOnlineIpListResponse{
				alice:   {Name: alice, Ips: map[string]int64{"2001:db8::1": ts + 1, "192.0.2.2": ts}},
				bob:     {Name: bob, Ips: map[string]int64{"192.0.2.3": ts - 1}},
				reverse: reverseList,
			},
			wantCode: http.StatusOK, supported: true, wantLists: []string{alice, bob, reverse},
			wantUsers: map[string][]testOnlineIP{
				"Alice@fixture.test": {{"192.0.2.2", "2024-01-01T00:00:01Z"}, {"2001:db8::1", "2024-01-01T00:00:02Z"}},
				"user-id":            {{"192.0.2.3", "2024-01-01T00:00:00Z"}},
			},
		},
		{
			name:   "rproof alone proves support but exposes no IPs or user",
			census: []string{reverse}, lists: map[string]*stats.GetStatsOnlineIpListResponse{reverse: reverseList},
			wantCode: http.StatusOK, supported: true, wantLists: []string{reverse},
		},
		{
			name:   "rproof map disappeared",
			census: []string{reverse}, listCodes: map[string]codes.Code{reverse: codes.NotFound},
			wantCode: http.StatusOK, wantLists: []string{reverse},
		},
		{name: "ambiguous empty census", wantCode: http.StatusOK},
		{name: "legacy census RPC", censusCode: codes.Unimplemented, wantCode: http.StatusOK},
		{name: "legacy list RPC", census: []string{alice}, listCodes: map[string]codes.Code{alice: codes.Unimplemented}, wantCode: http.StatusOK, wantLists: []string{alice}},
		{name: "map disappeared", census: []string{alice}, listCodes: map[string]codes.Code{alice: codes.NotFound}, wantCode: http.StatusOK, wantLists: []string{alice}},
		{
			name: "empty map confirmed plus one disappeared", census: []string{alice, bob},
			lists: map[string]*stats.GetStatsOnlineIpListResponse{alice: {Name: alice}}, listCodes: map[string]codes.Code{bob: codes.NotFound},
			wantCode: http.StatusOK, supported: true, wantLists: []string{alice, bob},
		},
		{name: "unreachable Xray", censusCode: codes.Unavailable, wantCode: http.StatusServiceUnavailable},
		{
			name: "no partial snapshot after list timeout", census: []string{alice, bob},
			lists:     map[string]*stats.GetStatsOnlineIpListResponse{alice: {Name: alice, Ips: map[string]int64{"192.0.2.2": ts}}},
			listCodes: map[string]codes.Code{bob: codes.DeadlineExceeded}, wantCode: http.StatusServiceUnavailable, wantLists: []string{alice, bob},
		},
		{
			name: "wrong map identity", census: []string{alice},
			lists:    map[string]*stats.GetStatsOnlineIpListResponse{alice: {Name: bob}},
			wantCode: http.StatusServiceUnavailable, wantLists: []string{alice},
		},
		{
			name: "invalid IP", census: []string{alice},
			lists:    map[string]*stats.GetStatsOnlineIpListResponse{alice: {Name: alice, Ips: map[string]int64{"192.0.2.2:123": ts}}},
			wantCode: http.StatusServiceUnavailable, wantLists: []string{alice},
		},
		{
			name: "invalid timestamp", census: []string{alice},
			lists:    map[string]*stats.GetStatsOnlineIpListResponse{alice: {Name: alice, Ips: map[string]int64{"192.0.2.2": 1 << 62}}},
			wantCode: http.StatusServiceUnavailable, wantLists: []string{alice},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var methods, listNames []string
			rpc := grpc.NewServer(grpc.UnaryInterceptor(func(_ context.Context, req any, info *grpc.UnaryServerInfo, _ grpc.UnaryHandler) (any, error) {
				mu.Lock()
				defer mu.Unlock()
				methods = append(methods, info.FullMethod)
				switch info.FullMethod {
				case stats.StatsService_GetAllOnlineUsers_FullMethodName:
					if tc.censusCode != codes.OK {
						return nil, status.Error(tc.censusCode, "private RPC detail")
					}
					return &stats.GetAllOnlineUsersResponse{Users: tc.census}, nil
				case stats.StatsService_GetStatsOnlineIpList_FullMethodName:
					r := req.(*stats.GetStatsRequest)
					if r.GetReset_() {
						t.Error("online IP list requested a reset")
					}
					listNames = append(listNames, r.GetName())
					if code := tc.listCodes[r.GetName()]; code != codes.OK {
						return nil, status.Error(code, "private RPC detail")
					}
					if resp := tc.lists[r.GetName()]; resp != nil {
						return resp, nil
					}
				}
				t.Errorf("unexpected RPC %s", info.FullMethod)
				return nil, status.Error(codes.Internal, "unexpected RPC")
			}))
			stats.RegisterStatsServiceServer(rpc, stats.UnimplementedStatsServiceServer{})
			listener, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			serveDone := make(chan struct{})
			go func() { defer close(serveDone); _ = rpc.Serve(listener) }()
			t.Cleanup(func() { rpc.Stop(); <-serveDone })

			srv := newOnlineIPHTTPFixture(t, listener.Addr().String())
			for _, auth := range []string{"", "Bearer wrong", "Basic synthetic-test"} {
				for _, path := range []string{"/stats", "/online-ips"} {
					checkOnlineIPStatus(t, srv, http.MethodGet, path, auth, http.StatusUnauthorized)
				}
			}
			checkOnlineIPStatus(t, srv, http.MethodPost, "/online-ips", "Bearer synthetic-test", http.StatusMethodNotAllowed)
			mu.Lock()
			if len(methods) != 0 {
				t.Error("unauthenticated/disallowed requests reached gRPC")
			}
			mu.Unlock()

			before := time.Now()
			body := checkOnlineIPStatus(t, srv, http.MethodGet, "/online-ips", "Bearer synthetic-test", tc.wantCode)
			if tc.wantCode == http.StatusOK {
				want := tc.wantUsers
				if want == nil {
					want = map[string][]testOnlineIP{}
				}
				checkOnlineIPSnapshot(t, body, tc.supported, want, before)
			} else if string(body) != "{\"error\":\"Online IP snapshot unavailable\"}\n" {
				t.Fatalf("failure leaked detail or resembled a snapshot: %s", body)
			}

			// Existing /online still uses the independent log tracker and response shape.
			body = checkOnlineIPStatus(t, srv, http.MethodGet, "/online", "Bearer synthetic-test", http.StatusOK)
			var legacy map[string]json.RawMessage
			if err := json.Unmarshal(body, &legacy); err != nil || len(legacy) != 3 || string(legacy["users"]) != "{}" || legacy["timeoutMs"] == nil || legacy["updatedAt"] == nil {
				t.Fatalf("legacy /online shape changed: %s", body)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(methods) != 1+len(tc.wantLists) || methods[0] != stats.StatsService_GetAllOnlineUsers_FullMethodName || !reflect.DeepEqual(listNames, tc.wantLists) {
				t.Errorf("unexpected RPC trace: %v %v", methods, listNames)
			}
		})
	}
}

type testOnlineIP struct {
	IP       string `json:"ip"`
	LastSeen string `json:"lastSeen"`
}

func newOnlineIPHTTPFixture(t *testing.T, addr string) *httptest.Server {
	t.Helper()
	cfg := &Config{Token: "synthetic-test", XrayAPI: addr, HTTPMutationPolicy: "deny"}
	xc, err := NewXrayClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(xc.Close)
	mux := http.NewServeMux()
	(&API{cfg: cfg, xrayClient: xc}).RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	srv.Client().Timeout = 10 * time.Second
	t.Cleanup(srv.Close)
	return srv
}

func checkOnlineIPStatus(t *testing.T, srv *httptest.Server, method, path, auth string, want int) []byte {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", auth)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != want {
		t.Fatalf("%s %s: HTTP %d, want %d: %s", method, path, resp.StatusCode, want, body)
	}
	if path == "/online-ips" && (want == http.StatusOK || want == http.StatusServiceUnavailable) &&
		(resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("Content-Type") != "application/json") {
		t.Errorf("missing private JSON response headers: %v", resp.Header)
	}
	return body
}

func checkOnlineIPSnapshot(t *testing.T, body []byte, supported bool, want map[string][]testOnlineIP, before time.Time) {
	t.Helper()
	var got struct {
		Supported *bool                     `json:"supported"`
		Users     map[string][]testOnlineIP `json:"users"`
		UpdatedAt string                    `json:"updatedAt"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Supported == nil || *got.Supported != supported || !reflect.DeepEqual(got.Users, want) {
		t.Fatalf("expected supported=%t with users=%#v; got %s", supported, want, body)
	}
	at, err := time.Parse(time.RFC3339Nano, got.UpdatedAt)
	if err != nil || at.Location() != time.UTC || at.Before(before) || at.After(time.Now()) {
		t.Errorf("invalid snapshot timestamp: %q", got.UpdatedAt)
	}
}
