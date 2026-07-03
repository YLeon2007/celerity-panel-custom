package main

import (
	"bufio"
	"context"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

const defaultOnlineTimeout = 45 * time.Second

var acceptedLogRe = regexp.MustCompile(`from\s+(?:tcp:)?([^\s:]+):\d+\s+accepted\s+([^\s]+)\s+\[([^\]\s]+)\s+->\s+([^\]]+)\]\s+email:\s+([^\s]+)`)

type XrayAcceptedEvent struct {
	UserID   string    `json:"userId"`
	ClientIP string    `json:"clientIp,omitempty"`
	Target   string    `json:"target,omitempty"`
	Inbound  string    `json:"inbound,omitempty"`
	Outbound string    `json:"outbound,omitempty"`
	SeenAt   time.Time `json:"seenAt"`
}

type OnlineUserState struct {
	Online     bool      `json:"online"`
	LastSeenAt time.Time `json:"lastSeenAt"`
	Source     string    `json:"source"`
	ClientIP   string    `json:"clientIp,omitempty"`
	Inbound    string    `json:"inbound,omitempty"`
	Outbound   string    `json:"outbound,omitempty"`
	Target     string    `json:"target,omitempty"`
}

type OnlineTracker struct {
	mu      sync.RWMutex
	timeout time.Duration
	users   map[string]OnlineUserState
}

func NewOnlineTracker(timeout time.Duration) *OnlineTracker {
	if timeout <= 0 {
		timeout = defaultOnlineTimeout
	}
	return &OnlineTracker{timeout: timeout, users: make(map[string]OnlineUserState)}
}

func ParseXrayAcceptedLogLine(line string) (XrayAcceptedEvent, bool) {
	m := acceptedLogRe.FindStringSubmatch(line)
	if len(m) != 6 {
		return XrayAcceptedEvent{}, false
	}
	userID := strings.TrimSpace(m[5])
	if userID == "" {
		return XrayAcceptedEvent{}, false
	}
	return XrayAcceptedEvent{
		ClientIP: strings.TrimSpace(m[1]),
		Target:   strings.TrimSpace(m[2]),
		Inbound:  strings.TrimSpace(m[3]),
		Outbound: strings.TrimSpace(m[4]),
		UserID:   userID,
	}, true
}

func (t *OnlineTracker) MarkAccepted(event XrayAcceptedEvent, now time.Time) {
	userID := strings.TrimSpace(event.UserID)
	if userID == "" {
		return
	}
	if now.IsZero() {
		now = time.Now()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.users[userID] = OnlineUserState{
		Online:     true,
		LastSeenAt: now,
		Source:     "xray-log",
		ClientIP:   event.ClientIP,
		Inbound:    event.Inbound,
		Outbound:   event.Outbound,
		Target:     event.Target,
	}
}

func (t *OnlineTracker) Snapshot(now time.Time) map[string]OnlineUserState {
	if now.IsZero() {
		now = time.Now()
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string]OnlineUserState, len(t.users))
	for userID, state := range t.users {
		state.Online = now.Sub(state.LastSeenAt) <= t.timeout
		if !state.Online {
			state.Source = "timeout"
		}
		out[userID] = state
	}
	return out
}

func (t *OnlineTracker) RunJournalWatcher(ctx context.Context) {
	for {
		if err := t.runJournalWatcherOnce(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[online] journal watcher stopped: %v; retrying in 5s", err)
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
				return
			}
			continue
		}
		return
	}
}

func (t *OnlineTracker) runJournalWatcherOnce(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "journalctl", "-u", "xray", "-f", "-o", "cat", "--no-pager")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		if event, ok := ParseXrayAcceptedLogLine(scanner.Text()); ok {
			t.MarkAccepted(event, time.Now())
		}
	}
	if scanErr := scanner.Err(); scanErr != nil && ctx.Err() == nil {
		_ = cmd.Wait()
		return scanErr
	}
	return cmd.Wait()
}
