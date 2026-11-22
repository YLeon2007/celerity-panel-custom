package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	handler "github.com/xtls/xray-core/app/proxyman/command"
	stats "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/grpc"
)

const observationFixtureID = "00000000000000000123abcd"
const observationFixtureChallenge = "abcdef0123456789abcdef0123456789"

func observationURL(linkID, port, digest string) string {
	return "/rebuild/reverse-observation/" + linkID + "?port=" + port + "&identity=" + digest + "&challenge=" + observationFixtureChallenge
}

func TestReverseObservationAdmissionAndAccounting(t *testing.T) {
	identity := strings.Repeat("a", 64)
	valid := observationURL(observationFixtureID, "25000", identity)
	a := &API{cfg: &Config{Token: "synthetic-only", XrayAPI: "127.0.0.1:25001"}, xrayClient: &XrayClient{}}
	mux := http.NewServeMux()
	a.RegisterRoutes(mux)
	for i := 0; i < cap(a.reverseObservations); i++ {
		a.reverseObservations <- struct{}{}
	}
	for _, tc := range []struct {
		url    string
		bearer bool
		status int
	}{
		{valid, false, 401},
		{valid + "&port=25000", true, 400},
		{valid + "&extra=1", true, 400},
		{strings.Replace(valid, "25000", "025000", 1), true, 400},
		{strings.Replace(valid, "25000", "65536", 1), true, 400},
		{strings.Replace(valid, identity, strings.ToUpper(identity), 1), true, 400},
		{strings.Replace(valid, observationFixtureID, "0123abcd", 1), true, 400},
		{strings.Replace(valid, observationFixtureChallenge, "x", 1), true, 400},
		{valid, true, 503},
	} {
		r := httptest.NewRequest("GET", tc.url, nil)
		if tc.bearer {
			r.Header.Set("Authorization", "Bearer synthetic-only")
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != tc.status || strings.Contains(w.Body.String(), identity) {
			t.Fatalf("got HTTP %d; want %d without request identity", w.Code, tc.status)
		}
	}
	email := (reverseObservationSubject{linkID: observationFixtureID, identity: identity}).email()
	snap := ParseSnapshot(map[string]int64{
		"user>>>" + email + ">>>traffic>>>downlink": 8,
		"user>>>subscriber>>>traffic>>>downlink":    3,
		"outbound>>>route>>>traffic>>>downlink":     5,
	})
	if len(snap.Users) != 1 || snap.Users["subscriber"].Rx != 3 || snap.Node.Rx != 5 {
		t.Fatal("telemetry must not affect billing or ordinary subscriber and route counters")
	}
	tracker := NewOnlineTracker(time.Minute)
	tracker.MarkAccepted(XrayAcceptedEvent{UserID: email}, time.Now())
	tracker.MarkAccepted(XrayAcceptedEvent{UserID: "subscriber"}, time.Now())
	if state := tracker.Snapshot(time.Now()); len(state) != 1 || !state["subscriber"].Online {
		t.Fatal("telemetry must not appear in agent online listing")
	}
}

type reverseFixtureSample struct {
	at    time.Time
	value int64
}

type reverseFixtureStats struct {
	stats.StatsServiceClient
	name    string
	samples chan reverseFixtureSample
}

func (s *reverseFixtureStats) GetStats(ctx context.Context, req *stats.GetStatsRequest, opts ...grpc.CallOption) (*stats.GetStatsResponse, error) {
	resp, err := s.StatsServiceClient.GetStats(ctx, req, opts...)
	if err == nil && !req.GetReset_() && req.GetName() == s.name && resp.GetStat().GetName() == s.name {
		// Signal the test, never enter /stats here: the product may hold a
		// mutex until this RPC returns. No RPC values or options are changed.
		select {
		case s.samples <- reverseFixtureSample{time.Now(), resp.GetStat().GetValue()}:
		default:
		}
	}
	return resp, err
}

const reverseFixtureSubscriber = "client-fixture"

func checkReverseWithStats(t *testing.T, c *XrayClient, cfg *Config, connected bool) {
	t.Helper()
	identity, port := os.Getenv("C3_REVERSE_IDENTITY"), os.Getenv("C3_REVERSE_PORT")
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 || !reverseIdentity.MatchString(identity) {
		t.Fatal("malformed fixture tuple")
	}
	trafficAddr := os.Getenv("C3_REVERSE_TRAFFIC")
	if host, _, err := net.SplitHostPort(trafficAddr); err != nil || host != "127.0.0.1" {
		t.Fatal("fixture traffic ingress must be loopback")
	}
	email := (reverseObservationSubject{linkID: observationFixtureID, identity: identity}).email()
	tap := &reverseFixtureStats{
		StatsServiceClient: c.stats,
		name:               "user>>>" + email + ">>>traffic>>>downlink",
		samples:            make(chan reverseFixtureSample, 2),
	}
	c.stats = tap
	mux := http.NewServeMux()
	(&API{cfg: cfg, xrayClient: c}).RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()
	client := server.Client()
	client.Timeout = 15 * time.Second
	get := func(path string) (*http.Response, error) {
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		return client.Do(req)
	}
	pulse := func() {
		// Actual application bytes, echoed via the composed receiver and the
		// live native reverse tunnel. Nothing writes or mocks a stats counter.
		payload := bytes.Repeat([]byte("x"), 64<<10)
		echoClient := &http.Client{Timeout: 2 * time.Second,
			Transport: &http.Transport{DisableKeepAlives: true}}
		defer echoClient.CloseIdleConnections()
		res, err := echoClient.Post("http://"+trafficAddr, "application/octet-stream", bytes.NewReader(payload))
		if err != nil {
			t.Fatal("reverse echo request failed")
		}
		defer res.Body.Close()
		body, err := io.ReadAll(io.LimitReader(res.Body, int64(len(payload)+1)))
		if err != nil || res.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
			t.Fatal("reverse echo did not return the real payload")
		}
	}
	read := func(name string) int64 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		res, err := tap.StatsServiceClient.GetStats(ctx, &stats.GetStatsRequest{Name: name})
		if err != nil || res.GetStat().GetName() != name || res.GetStat().GetValue() < 0 {
			t.Fatal("fixture's independent non-resetting GetStats failed")
		}
		return res.GetStat().GetValue()
	}
	subscriberCounter := "user>>>" + reverseFixtureSubscriber + ">>>traffic>>>downlink"
	takeStats := func(label string, before reverseFixtureSample) int64 {
		start := time.Now()
		res, err := get("/stats")
		if err != nil {
			t.Fatal("GET /stats failed")
		}
		defer res.Body.Close()
		var got struct {
			Users map[string]UserTraffic `json:"users"`
			Node  *UserTraffic           `json:"node"`
		}
		if res.StatusCode != http.StatusOK || res.Header.Get("Content-Type") != "application/json" ||
			json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&got) != nil || got.Node == nil ||
			len(got.Users) != 1 || got.Users[reverseFixtureSubscriber].Rx < 64<<10 || got.Users[reverseFixtureSubscriber].Tx < 64<<10 {
			t.Fatalf("%s: /stats did not report real subscriber bytes without reverse telemetry", label)
		}
		end := time.Now()
		if start.Before(before.at) || end.Sub(before.at) >= 11*time.Second {
			t.Fatalf("%s: /stats outside the 11s sampling window", label)
		}
		if read(subscriberCounter) != 0 {
			t.Fatalf("%s: /stats did not reset the subscriber counter", label)
		}
		raw := read(tap.name)
		t.Logf("/stats %s: HTTP 200, subscriber reset, reverse raw=%d, +%v..%v from first GetStats",
			label, raw, start.Sub(before.at).Round(time.Microsecond), end.Sub(before.at).Round(time.Microsecond))
		return raw
	}
	if connected {
		pulse() // Accumulate an actual positive baseline before observation starts.
	}
	type observationHTTP struct {
		status   int
		jsonType bool
		body     []byte
		err      error
	}
	done := make(chan observationHTTP, 1)
	start := time.Now()
	go func() {
		res, err := get(observationURL(observationFixtureID, port, identity))
		if err != nil {
			done <- observationHTTP{err: err}
			return
		}
		defer res.Body.Close()
		body, err := io.ReadAll(io.LimitReader(res.Body, 1024))
		done <- observationHTTP{res.StatusCode, res.Header.Get("Content-Type") == "application/json", body, err}
	}()
	var before reverseFixtureSample
	select {
	case before = <-tap.samples:
	case res := <-done:
		t.Fatalf("observation completed before first successful GetStats (HTTP %d)", res.status)
	case <-time.After(3 * time.Second):
		t.Fatal("no first GetStats in observation")
	}
	if before.value <= 0 {
		t.Fatal("observation must start with accumulated reverse bytes")
	}
	postReset := takeStats("after-baseline", before)
	if connected {
		// Force real growth well inside the window, then erase a second live
		// interval on the baseline. A single early reset alone can miss it.
		pulse()
		pulse()
		grown := read(tap.name)
		if grown <= before.value || grown <= postReset {
			t.Fatalf("reverse traffic did not grow past the baseline: first=%d after /stats=%d grown=%d", before.value, postReset, grown)
		}
		t.Logf("live reverse grew to %d after first /stats (baseline=%d)", grown, before.value)
		takeStats("after-growth", before)
	}
	res := <-done
	elapsed := time.Since(start)
	if res.err != nil || res.status != http.StatusOK || !res.jsonType {
		t.Fatalf("observation RPC/HTTP failure (HTTP %d)", res.status)
	}
	var after reverseFixtureSample
	select {
	case after = <-tap.samples:
	default:
		t.Fatal("no second successful GetStats; did not exercise the full observation")
	}
	window := after.at.Sub(before.at)
	if window < 11*time.Second || elapsed >= 15*time.Second {
		t.Fatalf("unexpected observation sample: window=%v HTTP=%v", window, elapsed)
	}
	if !connected && after.value != postReset {
		t.Fatalf("cut reverse counter changed after /stats: %d -> %d", postReset, after.value)
	}
	trueReply := fmt.Sprintf("{\"version\":1,\"linkId\":%q,\"port\":%d,\"challenge\":%q,\"established\":true}\n", observationFixtureID, n, observationFixtureChallenge)
	falseReply := strings.Replace(trueReply, `"established":true`, `"established":false`, 1)
	if string(res.body) != trueReply && string(res.body) != falseReply {
		t.Fatal("invalid reverse observation response contract")
	}
	established := string(res.body) == trueReply
	t.Logf("observation: established=%t first=%d second=%d window=%v HTTP=%v",
		established, before.value, after.value, window.Round(time.Millisecond), elapsed.Round(time.Millisecond))
	if established != connected {
		t.Errorf("reverse with GET /stats: established=%t, want %t", established, connected)
	}
}

// The driver owns the exact pinned core, checks namespace isolation and runs
// the production HTTP router on a real loopback listener with real Xray RPCs.
func TestRealReverseObservation(t *testing.T) {
	phase := os.Getenv("C3_REVERSE_PHASE")
	if phase == "" {
		t.Skip("requires the pinned loopback fixture")
	}
	parent := os.Getenv("C3_REVERSE_PARENT_NETNS")
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || parent == "" || ns == parent {
		t.Fatal("requires isolated netns")
	}
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
		t.Fatal("requires loopback-only netns")
	}
	addr := os.Getenv("C3_REVERSE_API")
	if host, _, err := net.SplitHostPort(addr); err != nil || host != "127.0.0.1" {
		t.Fatal("fixture API must be loopback")
	}
	cfg := &Config{Token: "fixture-only", XrayAPI: addr}
	c, err := NewXrayClient(cfg)
	if err != nil {
		t.Fatal("cannot create Xray client")
	}
	defer c.Close()
	if phase == "connected-with-stats" || phase == "cut-with-stats" {
		checkReverseWithStats(t, c, cfg, phase == "connected-with-stats")
		return
	}
	if phase == "add-anonymous-account" {
		// Add only the negative control to the running receiver. The Xray
		// CLI adu skips email-free accounts.
		id := os.Getenv("C3_REVERSE_ANONYMOUS")
		if !reverseUUID.MatchString(id) {
			t.Fatal("invalid anonymous fixture UUID")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, err := c.proxyman.AlterInbound(ctx, &handler.AlterInboundRequest{
			Tag: (reverseObservationSubject{linkID: observationFixtureID}).connector(),
			Operation: serial.ToTypedMessage(&handler.AddUserOperation{User: &protocol.User{
				Account: serial.ToTypedMessage(&vless.Account{Id: id, Reverse: &vless.Reverse{Tag: "anonymous-native-egress"}}),
			}}),
		})
		if err != nil {
			t.Fatalf("add anonymous fixture: %v", err)
		}
		t.Log(phase)
		return
	}
	mux := http.NewServeMux()
	(&API{cfg: cfg, xrayClient: c}).RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()
	if phase == "connected" || phase == "cut" || phase == "reconnected" {
		ctx, cancel := context.WithTimeout(context.Background(), 22*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "node", os.Getenv("C3_REVERSE_PANEL_HELPER"), phase,
			os.Getenv("C3_REVERSE_FIXTURE"), os.Getenv("C3_REVERSE_MONGO_PORT"), server.URL)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("panel %s: %v\n%s", phase, err, out)
		}
		t.Log(strings.TrimSpace(string(out)))
		return
	}

	linkID, port, identity := observationFixtureID, os.Getenv("C3_REVERSE_PORT"), os.Getenv("C3_REVERSE_IDENTITY")
	switch phase {
	case "wrong-full-id":
		linkID = "f" + linkID[1:]
	case "wrong-identity":
		identity = strings.Repeat("0", 64)
	case "wrong-port":
		port = "1"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n <= 0 || n > 65535 || !reverseIdentity.MatchString(identity) {
		t.Fatal("malformed fixture tuple")
	}
	req, err := http.NewRequest(http.MethodGet, server.URL+observationURL(linkID, port, identity), nil)
	if err != nil {
		t.Fatal("cannot create request")
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	client := server.Client()
	client.Timeout = 15 * time.Second
	start := time.Now()
	res, err := client.Do(req)
	if err != nil {
		t.Fatal("HTTP observation request failed")
	}
	defer res.Body.Close()
	if phase == "api-unavailable" {
		if res.StatusCode != 503 {
			t.Fatalf("unavailable API yielded %d", res.StatusCode)
		}
		t.Log("api-unavailable: HTTP 503")
		return
	}
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("%s: HTTP %d", phase, res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1024))
	if err != nil {
		t.Fatal("read failed")
	}
	want := fmt.Sprintf("{\"version\":1,\"linkId\":%q,\"port\":%d,\"challenge\":%q,\"established\":false}\n", linkID, n, observationFixtureChallenge)
	if !json.Valid(body) || string(body) != want {
		t.Fatalf("%s: unexpected response (matches contract=%t)", phase, string(body) == want)
	}
	t.Logf("%s: established=false elapsed=%v", phase, time.Since(start).Round(time.Millisecond))
}
