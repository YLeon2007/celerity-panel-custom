package main

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"

	stats "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type onlineIP struct {
	IP       string    `json:"ip"`
	LastSeen time.Time `json:"lastSeen"`
}

type onlineIPSnapshot struct {
	Supported bool                  `json:"supported"`
	Users     map[string][]onlineIP `json:"users"`
	UpdatedAt time.Time             `json:"updatedAt"`
}

// GET /online-ips reads native Xray samples, independently of /online and /stats.
func (a *API) handleOnlineIPs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	snapshot, err := a.xrayClient.queryOnlineIPs(ctx)
	if err != nil {
		// Do not expose raw gRPC errors, account names or partial observations.
		jsonErr(w, http.StatusServiceUnavailable, "Online IP snapshot unavailable")
		return
	}
	snapshot.UpdatedAt = time.Now().UTC()
	jsonOK(w, snapshot)
}

func (c *XrayClient) queryOnlineIPs(ctx context.Context) (onlineIPSnapshot, error) {
	empty := onlineIPSnapshot{Users: make(map[string][]onlineIP)}
	if c == nil || c.stats == nil {
		return empty, fmt.Errorf("Xray StatsService client not configured")
	}
	census, err := c.stats.GetAllOnlineUsers(ctx, &stats.GetAllOnlineUsersRequest{})
	if status.Code(err) == codes.Unimplemented {
		return empty, nil
	}
	if err != nil {
		return empty, err
	}

	// In Xray v1.260206.0 the census contains full online-map names, only
	// for nonempty maps. Empty cannot distinguish disabled policy from idle
	// or not-yet-observed accounts. Require a successful per-user list from
	// this snapshot; do not infer support from the census RPC or disk config.
	snapshot := onlineIPSnapshot{Users: make(map[string][]onlineIP)}
	seen := make(map[string]bool)
	for _, name := range census.GetUsers() {
		email, ok := strings.CutPrefix(name, "user>>>")
		if !ok {
			continue
		}
		email, ok = strings.CutSuffix(email, ">>>online")
		if !ok || strings.TrimSpace(email) == "" || isReverseObservationEmail(email) || seen[name] {
			continue
		}
		seen[name] = true
		list, err := c.stats.GetStatsOnlineIpList(ctx, &stats.GetStatsRequest{Name: name, Reset_: false})
		switch status.Code(err) {
		case codes.NotFound:
			// The two reads are not atomic. A missing map is not evidence of
			// support, but it doesn't invalidate other successful lists.
			continue
		case codes.Unimplemented:
			return empty, nil
		case codes.OK:
		default:
			return empty, err
		}
		if list.GetName() != name {
			return empty, fmt.Errorf("unexpected Xray online-map name")
		}
		snapshot.Supported = true
		ips := make([]onlineIP, 0, len(list.GetIps()))
		for ip, sec := range list.GetIps() {
			addr, err := netip.ParseAddr(ip)
			// Xray emits Unix seconds. Bound to positive RFC3339-representable
			// values before constructing a time.Time for the JSON encoder.
			if err != nil || addr.Zone() != "" || sec <= 0 || sec > 253402300799 {
				return empty, fmt.Errorf("invalid Xray online IP sample")
			}
			ips = append(ips, onlineIP{IP: ip, LastSeen: time.Unix(sec, 0).UTC()})
		}
		if len(ips) != 0 {
			sort.Slice(ips, func(i, j int) bool { return ips[i].IP < ips[j].IP })
			snapshot.Users[email] = ips
		}
	}
	return snapshot, nil
}
