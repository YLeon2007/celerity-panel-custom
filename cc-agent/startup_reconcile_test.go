package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func awaitStartupSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatal("startup reconciliation did not reach expected point")
	}
}

func TestStartupReconcileCancelBeforeLateTimerDoesNotFlush(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var flushes, restarts atomic.Int32
	r := startStartupReconcile(startupReconcileDeps{
		wait: func(context.Context, time.Duration) bool {
			close(entered)
			<-release
			return true // timer won the race with cancellation
		},
		flush:    func() (bool, error) { flushes.Add(1); return true, nil },
		lastSync: func() time.Time { return time.Time{} },
		restart:  func(context.Context) ([]byte, error) { restarts.Add(1); return nil, nil },
		discard:  func(context.Context) error { return nil },
	})
	awaitStartupSignal(t, entered)
	r.Cancel() // production cancels before HTTP shutdown and joins afterward
	close(release)
	r.Stop()
	if flushes.Load() != 0 || restarts.Load() != 0 {
		t.Fatalf("work after cancel: flush=%d restart=%d", flushes.Load(), restarts.Load())
	}
}

func TestStartupReconcileStopDuringGrace(t *testing.T) {
	enteredGrace := make(chan struct{})
	var flushes, restarts, discards atomic.Int32
	r := startStartupReconcile(startupReconcileDeps{
		wait: func(ctx context.Context, d time.Duration) bool {
			if d == 3*time.Second {
				return true
			}
			if d != 15*time.Second {
				t.Errorf("wait = %v", d)
			}
			close(enteredGrace)
			<-ctx.Done()
			return false
		},
		flush:    func() (bool, error) { flushes.Add(1); return true, nil },
		lastSync: func() time.Time { return time.Time{} },
		restart:  func(context.Context) ([]byte, error) { restarts.Add(1); return nil, nil },
		discard:  func(context.Context) error { discards.Add(1); return nil },
	})
	awaitStartupSignal(t, enteredGrace)
	r.Stop()
	if flushes.Load() != 1 || restarts.Load() != 0 || discards.Load() != 0 {
		t.Fatalf("work after stop: flush=%d restart=%d discard=%d", flushes.Load(), restarts.Load(), discards.Load())
	}
}

// A command may already have been submitted to systemd when shutdown begins.
// We join only the local invocation, never infer that its job is quiescent.
func TestStartupReconcileStopJoinsStartedRestart(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	cancelled := make(chan struct{})
	var flushes, restarts, discards atomic.Int32
	r := startStartupReconcile(startupReconcileDeps{
		wait:     func(ctx context.Context, d time.Duration) bool { return ctx.Err() == nil },
		flush:    func() (bool, error) { flushes.Add(1); return true, nil },
		lastSync: func() time.Time { return time.Time{} },
		restart: func(ctx context.Context) ([]byte, error) {
			restarts.Add(1)
			close(started)
			<-ctx.Done()
			close(cancelled)
			<-release // simulates a local command that hasn't returned yet
			return nil, ctx.Err()
		},
		discard: func(context.Context) error { discards.Add(1); return nil },
	})
	awaitStartupSignal(t, started)
	stopped := make(chan struct{})
	go func() { r.Stop(); close(stopped) }()
	awaitStartupSignal(t, cancelled)
	select {
	case <-stopped:
		t.Fatal("Stop returned while local restart invocation was active")
	default:
	}
	close(release)
	awaitStartupSignal(t, stopped)
	if flushes.Load() != 2 || restarts.Load() != 1 || discards.Load() != 0 {
		t.Fatalf("unexpected work: flush=%d restart=%d discard=%d", flushes.Load(), restarts.Load(), discards.Load())
	}
}

func TestStartupReconcileStopJoinsInflightReflushBeforeRestart(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var flushes, restarts atomic.Int32
	r := startStartupReconcile(startupReconcileDeps{
		wait: func(ctx context.Context, d time.Duration) bool { return ctx.Err() == nil },
		flush: func() (bool, error) {
			if flushes.Add(1) == 2 {
				close(entered)
				<-release
			}
			return true, nil
		},
		lastSync: func() time.Time { return time.Time{} },
		restart:  func(context.Context) ([]byte, error) { restarts.Add(1); return nil, nil },
		discard:  func(context.Context) error { return nil },
	})
	awaitStartupSignal(t, entered)
	r.Cancel()
	stopped := make(chan struct{})
	go func() { r.Stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Stop returned during in-flight reflush")
	default:
	}
	close(release)
	awaitStartupSignal(t, stopped)
	if flushes.Load() != 2 || restarts.Load() != 0 {
		t.Fatalf("work after stop: flush=%d restart=%d", flushes.Load(), restarts.Load())
	}
}

func TestStartupReconcileStopDuringInitialWait(t *testing.T) {
	entered := make(chan struct{})
	var flushes, restarts, discards atomic.Int32
	r := startStartupReconcile(startupReconcileDeps{
		wait: func(ctx context.Context, d time.Duration) bool {
			if d != 3*time.Second {
				t.Errorf("wait = %v", d)
			}
			close(entered)
			<-ctx.Done()
			return false
		},
		flush:    func() (bool, error) { flushes.Add(1); return true, nil },
		lastSync: func() time.Time { return time.Time{} },
		restart:  func(context.Context) ([]byte, error) { restarts.Add(1); return nil, nil },
		discard:  func(context.Context) error { discards.Add(1); return nil },
	})
	awaitStartupSignal(t, entered)
	r.Stop()
	if flushes.Load() != 0 || restarts.Load() != 0 || discards.Load() != 0 {
		t.Fatalf("work after stop: flush=%d restart=%d discard=%d", flushes.Load(), restarts.Load(), discards.Load())
	}
}
