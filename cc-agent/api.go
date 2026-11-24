package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// API holds dependencies for the HTTP handler layer
type API struct {
	cfg           *Config
	userStore     *UserStore
	xrayClient    *XrayClient
	persister     *ConfigPersister
	onlineTracker *OnlineTracker
	// shipper is nil when access-log collection is disabled.
	shipper *Shipper
	// Bound observations independently of the existing HTTP endpoints.
	reverseObservations chan struct{}
	// Hold until the recovery census, mutations, and gate publication settle.
	recoverySync sync.Mutex
}

func (a *API) RegisterRoutes(mux *http.ServeMux) {
	a.reverseObservations = make(chan struct{}, 6)
	mux.HandleFunc("GET /health", a.auth(a.handleHealth))
	mux.HandleFunc("GET /xray-health", a.auth(xrayHealthHandler(a.probeXray)))
	mux.HandleFunc("GET /info", a.auth(a.handleInfo))
	mux.HandleFunc("POST /connect", a.auth(a.handleConnect))
	mux.HandleFunc("POST /sync", a.auth(a.denyHTTPMutation(a.handleSync)))
	mux.HandleFunc("POST /users", a.auth(a.denyHTTPMutation(a.handleAddUser)))
	mux.HandleFunc("DELETE /users/{email}", a.auth(a.denyHTTPMutation(a.handleRemoveUser)))
	mux.HandleFunc("GET /stats", a.auth(a.handleStats))
	mux.HandleFunc("GET /online", a.auth(a.handleOnline))
	mux.HandleFunc("GET /online-ips", a.auth(a.handleOnlineIPs))
	mux.HandleFunc("GET /rebuild/reverse-observation/{id}", a.auth(a.handleReverseObservation))
	mux.HandleFunc("POST /restart", a.auth(a.denyHTTPMutation(a.handleRestart)))
}

// denyHTTPMutation runs after authentication and before any handler reads a
// body or touches Xray, the user store, or the persister.
func (a *API) denyHTTPMutation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.cfg.HTTPMutationPolicy == "deny" {
			jsonErr(w, http.StatusForbidden, "HTTP mutation denied by policy")
			return
		}
		next(w, r)
	}
}

// auth middleware validates the Bearer token
func (a *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Bearer ")
		if token == "" || token == auth || token != a.cfg.Token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func jsonOK(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// The existing /stats handler clears counters and masks gRPC failures with
// zero traffic. Use the same local StatsService, without resetting counters.
func (a *API) probeXray(ctx context.Context) error {
	if a.xrayClient == nil {
		return fmt.Errorf("Xray API client not configured")
	}
	_, err := a.xrayClient.QueryStats(ctx, "", false)
	return err
}

// GET /health — simple liveness probe
func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]string{"status": "ok"})
}

// GET /info — version, uptime, user count
func (a *API) handleInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]any{
		"agent_version":  Version,
		"xray_version":   getXrayVersion(),
		"uptime_seconds": int(time.Since(startTime).Seconds()),
		"users_count":    a.userStore.Count(),
		"last_sync":      a.userStore.GetLastSync(),
	}
	if a.shipper != nil {
		info["access_logs"] = a.shipper.Status()
	} else {
		info["access_logs"] = ShipperStatus{Enabled: false}
	}
	jsonOK(w, info)
}

// POST /connect — handshake; panel calls this to verify connectivity
func (a *API) handleConnect(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]any{
		"status":        "connected",
		"agent_version": Version,
		"xray_version":  getXrayVersion(),
	})
}

// POST /sync — full user sync (replace all users)
func (a *API) handleSync(w http.ResponseWriter, r *http.Request) {
	// A request that starts in recovery must not fall through to the ordinary
	// sync path if another request opens the gate while its body is being read.
	recovering := a.userStore != nil && a.userStore.needsFullSync()
	var req struct {
		Users []*User `json:"users"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil || dec.Decode(new(json.RawMessage)) != io.EOF {
		jsonErr(w, http.StatusBadRequest, "One full users snapshot required")
		return
	}
	newMap, err := indexSnapshot(req.Users)
	if err != nil {
		jsonErr(w, http.StatusBadRequest, err.Error())
		return
	}
	lease := a.userStore.admitMutation()
	if lease == nil {
		jsonErr(w, http.StatusServiceUnavailable, "user store stopped")
		return
	}
	defer lease.Done()

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	if recovering || a.userStore.needsFullSync() {
		a.handleRecoverySync(ctx, w, lease, req.Users, newMap)
		return
	}

	current := a.userStore.List()
	currentMap := make(map[string]*User, len(current))
	for _, u := range current {
		currentMap[u.Email] = u
	}

	added, removed, errors := 0, 0, 0

	for email := range currentMap {
		if _, exists := newMap[email]; !exists {
			if err := a.xrayClient.RemoveUser(ctx, email); err != nil {
				log.Printf("[sync] Remove %s: %v", email, err)
				errors++
			} else {
				removed++
			}
		}
	}

	for email, u := range newMap {
		if _, exists := currentMap[email]; !exists {
			if err := a.xrayClient.AddUser(ctx, u); err != nil {
				log.Printf("[sync] Add %s: %v", email, err)
				errors++
			} else {
				added++
			}
		}
	}

	a.finishSync(w, lease, req.Users, added, removed, errors)
}

func (a *API) finishSync(w http.ResponseWriter, lease *mutationLease, users []*User, added, removed, errors int) {
	lease.Sync(users)
	a.persister.MarkDirty()
	a.userStore.SaveAsync() // Stop's final snapshot covers closed write admission.

	log.Printf("[sync] Done: +%d -%d errors=%d total=%d", added, removed, errors, len(users))
	jsonOK(w, map[string]any{
		"added":   added,
		"removed": removed,
		"errors":  errors,
		"total":   len(users),
	})
}

// Only a full sync can release a startup conflict.
func (a *API) waitingForSync(w http.ResponseWriter) bool {
	if !a.userStore.needsFullSync() {
		return false
	}
	jsonErr(w, http.StatusServiceUnavailable, "Waiting for full panel /sync")
	return true
}

// POST /users — add a single user
func (a *API) handleAddUser(w http.ResponseWriter, r *http.Request) {
	var u User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		jsonErr(w, http.StatusBadRequest, "Bad request: "+err.Error())
		return
	}
	if u.ID == "" || u.Email == "" {
		jsonErr(w, http.StatusBadRequest, "id and email are required")
		return
	}
	if a.waitingForSync(w) {
		return
	}
	lease := a.userStore.admitMutation()
	if lease == nil {
		jsonErr(w, http.StatusServiceUnavailable, "user store stopped")
		return
	}
	defer lease.Done()

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := a.xrayClient.AddUser(ctx, &u); err != nil {
		log.Printf("[api] AddUser %s: %v", u.Email, err)
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	lease.Add(&u)
	a.persister.MarkDirty()
	a.userStore.SaveAsync() // Stop's final snapshot covers closed write admission.

	jsonOK(w, map[string]string{"status": "ok"})
}

// DELETE /users/{email} — remove a single user
func (a *API) handleRemoveUser(w http.ResponseWriter, r *http.Request) {
	if a.waitingForSync(w) {
		return
	}
	lease := a.userStore.admitMutation()
	if lease == nil {
		jsonErr(w, http.StatusServiceUnavailable, "user store stopped")
		return
	}
	defer lease.Done()
	email := r.PathValue("email")
	if email == "" {
		jsonErr(w, http.StatusBadRequest, "email is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := a.xrayClient.RemoveUser(ctx, email); err != nil {
		// Log but don't fail — user may not exist in Xray (e.g. after restart)
		log.Printf("[api] RemoveUser %s: %v", email, err)
	}

	lease.Remove(email)
	a.persister.MarkDirty()
	a.userStore.SaveAsync() // Stop's final snapshot covers closed write admission.

	jsonOK(w, map[string]string{"status": "ok"})
}

// GET /stats — take one atomic snapshot from Xray (reset=true) and return
// { users: { <userId>: {tx, rx} }, node: {tx, rx} }.
// Users carry per-user uplink/downlink; node is the sum of outbound uplink/downlink
// across all non-API outbounds (i.e. real traffic that traversed Xray).
func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	rawStats, err := a.xrayClient.QueryStats(ctx, "", true)
	if err != nil {
		log.Printf("[stats] QueryStats: %v", err)
		jsonOK(w, map[string]any{
			"users": map[string]any{},
			"node":  map[string]int64{"tx": 0, "rx": 0},
		})
		return
	}

	snap := ParseSnapshot(rawStats)

	users := make(map[string]map[string]int64, len(snap.Users))
	for email, t := range snap.Users {
		if t.Tx == 0 && t.Rx == 0 {
			continue
		}
		users[email] = map[string]int64{"tx": t.Tx, "rx": t.Rx}
	}

	jsonOK(w, map[string]any{
		"users": users,
		"node":  map[string]int64{"tx": snap.Node.Tx, "rx": snap.Node.Rx},
	})
}

// GET /online — returns log-derived per-user online state.
func (a *API) handleOnline(w http.ResponseWriter, r *http.Request) {
	users := map[string]OnlineUserState{}
	if a.onlineTracker != nil {
		users = a.onlineTracker.Snapshot(time.Now())
	}
	jsonOK(w, map[string]any{
		"users":     users,
		"updatedAt": time.Now().UTC(),
		"timeoutMs": int(defaultOnlineTimeout / time.Millisecond),
	})
}

// POST /restart — restart Xray service. The on-disk config.json already carries
// the current user list (kept in sync by ConfigPersister), so Xray comes back up
// with the correct users on its own — no gRPC replay needed.
func (a *API) handleRestart(w http.ResponseWriter, r *http.Request) {
	if a.waitingForSync(w) {
		return
	}
	// Make sure the latest user set is persisted before the restart so the
	// reloaded Xray cannot pick up a stale snapshot.
	if _, err := a.persister.Flush(); err != nil {
		log.Printf("[api] Restart: config flush failed: %v", err)
	}
	// Flush itself can discover clients added since an empty startup load.
	if a.waitingForSync(w) {
		return
	}

	out, err := exec.Command("systemctl", "restart", "xray").CombinedOutput()
	if err != nil {
		log.Printf("[api] Restart xray error: %v, output: %s", err, out)
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Give Xray a moment to come up before returning, so a follow-up /sync from
	// the panel hits a live gRPC API.
	time.Sleep(2 * time.Second)

	log.Printf("[api] Xray restarted (%d users in config)", a.userStore.Count())
	jsonOK(w, map[string]string{"status": "ok", "users": fmt.Sprintf("%d", a.userStore.Count())})
}

// getXrayVersion reads the installed Xray version by running `xray version`
func getXrayVersion() string {
	out, err := exec.Command("xray", "version").Output()
	if err != nil {
		return "unknown"
	}
	lines := strings.SplitN(string(out), "\n", 2)
	if len(lines) == 0 {
		return "unknown"
	}
	// "Xray 1.8.24 (Xray, Penetrates Everything.) ..."
	parts := strings.Fields(lines[0])
	if len(parts) >= 2 {
		return parts[1]
	}
	return strings.TrimSpace(lines[0])
}
