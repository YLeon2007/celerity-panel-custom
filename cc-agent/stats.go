package main

import "strings"

// UserTraffic holds uplink/downlink bytes.
// For users: Tx = client uplink (client -> server), Rx = client downlink (server -> client).
// For the node: Tx/Rx are the sum of outbound uplink/downlink across all non-API outbounds,
// which is the real traffic that actually traversed Xray.
type UserTraffic struct {
	Tx int64 `json:"tx"` // uplink bytes
	Rx int64 `json:"rx"` // downlink bytes
}

// Snapshot is the parsed result of a single Xray QueryStats call with an empty
// pattern. Users is keyed by email (which equals the panel userId). Node is the
// aggregated node-level traffic derived from outbound stats.
type Snapshot struct {
	Users map[string]*UserTraffic
	Node  UserTraffic
}

// apiOutboundTag is the tag of the internal Xray API outbound; its counters
// represent gRPC control-plane traffic and must not be attributed to the node.
const apiOutboundTag = "API"

// ParseSnapshot converts a flat map of Xray stat names to a structured Snapshot.
// Expected stat name formats:
//   - user>>>{email}>>>traffic>>>{uplink|downlink}
//   - outbound>>>{tag}>>>traffic>>>{uplink|downlink}
//   - inbound>>>{tag}>>>traffic>>>{uplink|downlink}   (ignored here; reserved for future metrics)
func ParseSnapshot(rawStats map[string]int64) Snapshot {
	snap := Snapshot{
		Users: make(map[string]*UserTraffic, len(rawStats)/2),
	}

	for name, value := range rawStats {
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 || parts[2] != "traffic" {
			continue
		}
		kind, id, direction := parts[0], parts[1], parts[3]

		switch kind {
		case "user":
			if isReverseObservationEmail(id) {
				continue
			}
			ut := snap.Users[id]
			if ut == nil {
				ut = &UserTraffic{}
				snap.Users[id] = ut
			}
			switch direction {
			case "uplink":
				ut.Tx += value
			case "downlink":
				ut.Rx += value
			}
		case "outbound":
			if id == apiOutboundTag {
				continue
			}
			switch direction {
			case "uplink":
				snap.Node.Tx += value
			case "downlink":
				snap.Node.Rx += value
			}
		}
	}

	return snap
}
