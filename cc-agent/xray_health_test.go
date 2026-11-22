package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestXrayHealthHandler(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
		body string
	}{
		{"RPC succeeds with no traffic", nil, "{\"xray_status\":\"online\"}\n"},
		{"RPC fails", errors.New("private gRPC diagnostic"), "{\"xray_status\":\"offline\"}\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var calls int
			handler := xrayHealthHandler(func(ctx context.Context) error {
				calls++
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 3*time.Second {
					t.Fatal("probe must have a bounded deadline")
				}
				return tt.err
			})
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/xray-health", nil))
			if calls != 1 || res.Code != http.StatusOK || res.Body.String() != tt.body {
				t.Fatal("health response does not distinguish local RPC success/failure")
			}
			if res.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("health responses must not be cached")
			}
		})
	}
}
