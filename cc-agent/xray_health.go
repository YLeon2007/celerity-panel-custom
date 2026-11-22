package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// xrayHealthHandler reports local Xray API readiness separately from agent
// liveness. The probe must be read-only and must honor the deadline.
func xrayHealthHandler(probe func(context.Context) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		status := "online"
		if err := probe(ctx); err != nil {
			status = "offline"
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		// A local Xray failure is still a successful reply from the agent.
		_ = json.NewEncoder(w).Encode(map[string]string{"xray_status": status})
	}
}
