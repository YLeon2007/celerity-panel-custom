package main

import (
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
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/vless"
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
