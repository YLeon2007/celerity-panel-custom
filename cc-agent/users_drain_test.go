package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func awaitStore(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for store")
		return nil
	}
}

// The first sink is blocked during actual I/O; a second, accepted async Save
// must not overwrite it out of order, and Stop must join both before its final
// snapshot. A late Save cannot write after Stop acknowledges.
func TestUserStoreStopDrainsAcceptedSavesAndWritesLatestLast(t *testing.T) {
	s := NewUserStore(&Config{DataDir: t.TempDir()})
	s.Add(&User{ID: "first", Email: "first@example.org"})
	entered, release := make(chan struct{}), make(chan struct{})
	var mu sync.Mutex
	var snapshots []persistedData
	active, maxActive := 0, 0
	s.writeFile = func(path string, data []byte) error {
		var pd persistedData
		if err := json.Unmarshal(data, &pd); err != nil {
			return err
		}
		mu.Lock()
		snapshots = append(snapshots, pd)
		active++
		if active > maxActive {
			maxActive = active
		}
		n := len(snapshots)
		mu.Unlock()
		defer func() {
			mu.Lock()
			active--
			mu.Unlock()
		}()
		if n == 1 {
			close(entered)
			<-release
		}
		return os.WriteFile(path, data, 0600)
	}
	first := make(chan error, 1)
	go func() { first <- s.Save() }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("first Save never reached sink")
	}
	s.Add(&User{ID: "second", Email: "second@example.org"})
	if !s.SaveAsync() {
		t.Fatal("second Save not accepted")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- s.Stop() }()
	select {
	case err := <-stopped:
		t.Fatalf("Stop returned while write blocked: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := awaitStore(t, first); err != nil {
		t.Fatal(err)
	}
	if err := awaitStore(t, stopped); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		t.Fatal(err)
	}
	var pd persistedData
	if err := json.Unmarshal(data, &pd); err != nil {
		t.Fatal(err)
	}
	if len(pd.Users) != 2 {
		t.Fatalf("final snapshot contains %d users, want 2", len(pd.Users))
	}
	mu.Lock()
	count := len(snapshots)
	serial := maxActive
	mu.Unlock()
	if count != 3 { // first Save, queued async Save, one final Stop snapshot
		t.Fatalf("got %d writes, want 3", count)
	}
	firstUsers := len(snapshots[0].Users)
	secondUsers := len(snapshots[1].Users)
	finalUsers := len(snapshots[2].Users)
	if serial != 1 || firstUsers != 1 || secondUsers != 2 || finalUsers != 2 {
		t.Fatalf("writes not serialized/latest: max active=%d users per snapshot=%d,%d,%d", serial, firstUsers, secondUsers, finalUsers)
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); !errors.Is(err, errUserStoreStopped) {
		t.Fatalf("Save after Stop: %v", err)
	}
	if s.SaveAsync() {
		t.Fatal("SaveAsync accepted after Stop")
	}
	if s.Add(&User{ID: "late", Email: "late@example.org"}) || s.Remove("first@example.org") || s.Sync(nil) || s.SetLastSync(time.Now()) {
		t.Fatal("mutation accepted after Stop")
	}
	mu.Lock()
	lateCount := len(snapshots)
	mu.Unlock()
	if lateCount != count || s.Count() != 2 {
		t.Fatalf("state changed after Stop: writes=%d users=%d", lateCount, s.Count())
	}
}

func TestStoppedStoreRejectsHTTPMutationsWithoutAcknowledgingThem(t *testing.T) {
	s := NewUserStore(&Config{DataDir: t.TempDir()})
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	a := &API{userStore: s}
	for _, tc := range []struct {
		name, method, body string
		handler            http.HandlerFunc
	}{
		{"sync", "POST", `{"users":[]}`, a.handleSync},
		{"add", "POST", `{"id":"a","email":"a@b"}`, a.handleAddUser},
		{"remove", "DELETE", "", a.handleRemoveUser},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/users", strings.NewReader(tc.body))
			if tc.name == "remove" {
				req.SetPathValue("email", "a@b")
			}
			w := httptest.NewRecorder()
			tc.handler(w, req)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503", w.Code)
			}
		})
	}
}

func TestPeriodicStoreSaverJoinsBeforeStop(t *testing.T) {
	s := NewUserStore(&Config{DataDir: t.TempDir()})
	ticks := make(chan time.Time)
	stop := make(chan struct{})
	done := make(chan struct{})
	entered, release := make(chan struct{}), make(chan struct{})
	s.writeFile = func(path string, data []byte) error {
		select {
		case <-entered:
		default:
			close(entered)
			<-release
		}
		return os.WriteFile(path, data, 0600)
	}
	go func() {
		defer close(done)
		runPeriodicUserSaves(stop, ticks, s)
	}()
	ticks <- time.Now()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("periodic save never reached sink")
	}
	close(stop)
	select {
	case <-done:
		t.Fatal("periodic loop exited during blocked write")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("periodic loop did not join")
	}
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
}
