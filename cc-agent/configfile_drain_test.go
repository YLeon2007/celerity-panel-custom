package main

import (
	"bytes"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// The sink blocks at the actual write boundary, not at a mocked timer or handler.
func TestConfigPersisterStopWaitsForInFlightWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"inbounds":[{"tag":"managed","settings":{"clients":[]}}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	store := NewUserStore(&Config{DataDir: t.TempDir()})
	store.Add(&User{ID: "first", Email: "first@example.org"})
	p := NewConfigPersister(path, []InboundEntry{{Tag: "managed"}}, store)
	entered := make(chan struct{})
	release := make(chan struct{})
	var writes atomic.Int32
	p.writeFile = func(path string, data []byte) error {
		writes.Add(1)
		close(entered)
		<-release
		return atomicWriteFile(path, data)
	}
	go p.run()
	flushed := make(chan error, 1)
	go func() { _, err := p.Flush(); flushed <- err }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("flush did not reach write sink")
	}
	stopped := make(chan error, 1)
	go func() { stopped <- p.Stop() }()
	select {
	case err := <-stopped:
		t.Fatalf("Stop acknowledged while the write was still blocked: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-flushed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("flush did not finish")
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not finish")
	}
	store.Add(&User{ID: "second", Email: "second@example.org"})
	p.MarkDirty()
	if _, err := p.Flush(); err != errPersisterStopped {
		t.Fatalf("Flush after Stop: got %v, want stopped", err)
	}
	if got := writes.Load(); got != 1 {
		t.Fatalf("write after Stop acknowledgement: %d writes", got)
	}
}

func TestConfigPersisterStopDrainsPendingDebounceBeforeAcknowledging(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"inbounds":[{"tag":"managed","settings":{"clients":[]}}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	store := NewUserStore(&Config{DataDir: t.TempDir()})
	store.Add(&User{ID: "pending", Email: "pending@example.org"})
	p := NewConfigPersister(path, []InboundEntry{{Tag: "managed"}}, store)
	p.debounce = time.Hour // the debounce timer cannot fire during this test
	entered := make(chan struct{})
	release := make(chan struct{})
	p.writeFile = func(path string, data []byte) error {
		close(entered)
		<-release
		return atomicWriteFile(path, data)
	}
	go p.run()
	p.MarkDirty()
	stopped := make(chan error, 1)
	go func() { stopped <- p.Stop() }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop discarded a pending debounced change")
	}
	select {
	case err := <-stopped:
		t.Fatalf("Stop acknowledged before pending write finished: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not finish")
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(data, []byte("pending@example.org")) {
		t.Fatalf("pending change not durable after Stop: data=%s err=%v", data, err)
	}
	if err := p.Stop(); err != nil {
		t.Fatalf("repeated Stop: %v", err)
	}
}
