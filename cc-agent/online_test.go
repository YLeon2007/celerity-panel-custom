package main

import (
	"testing"
	"time"
)

func TestParseXrayAcceptedLogLine(t *testing.T) {
	line := `2026/07/03 18:58:10.551794 from 95.105.78.83:44286 accepted tcp:www.google.com:443 [vless-in -> portal-caf67d08] email: leon`

	event, ok := ParseXrayAcceptedLogLine(line)
	if !ok {
		t.Fatalf("expected accepted event")
	}
	if event.UserID != "leon" {
		t.Fatalf("UserID = %q, want leon", event.UserID)
	}
	if event.ClientIP != "95.105.78.83" {
		t.Fatalf("ClientIP = %q", event.ClientIP)
	}
	if event.Inbound != "vless-in" || event.Outbound != "portal-caf67d08" {
		t.Fatalf("route = %q -> %q", event.Inbound, event.Outbound)
	}
	if event.Target != "tcp:www.google.com:443" {
		t.Fatalf("Target = %q", event.Target)
	}
}

func TestOnlineTrackerExpiresAfterTimeout(t *testing.T) {
	base := time.Date(2026, 7, 3, 18, 58, 10, 0, time.UTC)
	tracker := NewOnlineTracker(45 * time.Second)

	tracker.MarkAccepted(XrayAcceptedEvent{UserID: "leon", ClientIP: "95.105.78.83", Inbound: "vless-in", Outbound: "portal-caf67d08"}, base)

	users := tracker.Snapshot(base.Add(44 * time.Second))
	if !users["leon"].Online {
		t.Fatalf("leon should still be online before timeout")
	}

	users = tracker.Snapshot(base.Add(46 * time.Second))
	if users["leon"].Online {
		t.Fatalf("leon should be offline after timeout")
	}
	if users["leon"].LastSeenAt.IsZero() {
		t.Fatalf("lastSeenAt should be preserved for offline users")
	}
}

func TestOnlineTrackerKeepsOnlyKnownUsers(t *testing.T) {
	tracker := NewOnlineTracker(45 * time.Second)
	tracker.MarkAccepted(XrayAcceptedEvent{UserID: ""}, time.Now())

	if got := tracker.Snapshot(time.Now()); len(got) != 0 {
		t.Fatalf("empty user IDs must be ignored, got %#v", got)
	}
}
