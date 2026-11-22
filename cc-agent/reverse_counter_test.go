package main

import (
	"context"
	"errors"
	"net"
	"testing"

	stats "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

// A successful resetting RPC returns the previous balance, not the new zero.
func TestReverseCounterWindow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		resets []int64
		after  int64
		want   bool
	}{
		{"growth without reset", nil, 101, true}, {"flat without reset", nil, 100, false},
		{"unobserved decrease", nil, 3, false}, {"reset alone", []int64{100}, 0, false},
		{"growth after reset", []int64{100}, 3, true}, {"equal after reset", []int64{100}, 100, true},
		{"growth before reset", []int64{101}, 0, true}, {"growth between resets", []int64{100, 1, 0}, 0, true},
		{"several resets without activity", []int64{100, 0}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := reverseCounterWindow{baseline: 100}
			for _, v := range tc.resets {
				w.reset(v)
			}
			if got := w.advanced(tc.after); got != tc.want {
				t.Fatalf("established=%t; want %t", got, tc.want)
			}
		})
	}
}

type reverseResetRPC struct {
	stats.StatsServiceClient
	p      peer.Peer
	result *stats.QueryStatsResponse
	err    error
}

func (s *reverseResetRPC) QueryStats(_ context.Context, _ *stats.QueryStatsRequest, opts ...grpc.CallOption) (*stats.QueryStatsResponse, error) {
	for _, o := range opts {
		if p, ok := o.(grpc.PeerCallOption); ok {
			*p.PeerAddr = s.p
		}
	}
	return s.result, s.err
}
func TestReverseResetAttribution(t *testing.T) {
	p := peer.Peer{Addr: &net.TCPAddr{Port: 7000}, LocalAddr: &net.TCPAddr{Port: 7001}}
	const name = "user>>>test-account>>>traffic>>>downlink"
	for _, tc := range []struct {
		kind  string
		reset bool
		want  bool
	}{
		{"same counter and peer", true, true}, {"other counter", true, false}, {"other transport", true, false},
		{"peer unavailable", true, false}, {"negative", true, false}, {"read only", false, false}, {"failed reset", true, false},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			row := &stats.Stat{Name: name, Value: 42}
			rpc := &reverseResetRPC{p: p, result: &stats.QueryStatsResponse{Stat: []*stats.Stat{row}}}
			c := &XrayClient{stats: rpc, counterGate: make(chan struct{}, 1)}
			w := &reverseCounterWindow{name: name, connection: counterPeer(p), baseline: 42}
			c.reverseWindows.Store(w, struct{}{})
			switch tc.kind {
			case "other counter":
				row.Name += "-other"
			case "other transport":
				rpc.p.LocalAddr = &net.TCPAddr{Port: 7002}
			case "peer unavailable":
				rpc.p = peer.Peer{}
			case "negative":
				row.Value = -1
			case "failed reset":
				rpc.err = errors.New("query failed")
			}
			_, err := c.QueryStats(context.Background(), "", tc.reset)
			if (err != nil) != (rpc.err != nil) {
				t.Fatalf("query error: %v", err)
			}
			if got := w.advanced(1); got != tc.want {
				t.Fatalf("mismatched attribution: got %t, want %t", got, tc.want)
			}
		})
	}
}
