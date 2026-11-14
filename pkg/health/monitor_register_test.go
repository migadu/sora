package health

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCheckRegisteredAfterStartRuns: the proxies register their remote lookup checks
// while they start, which is after the health monitor has started. Such a check must
// run like one registered before Start, or a lookup outage never shows up in the
// health data.
func TestCheckRegisteredAfterStartRuns(t *testing.T) {
	hm := NewHealthMonitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hm.Start(ctx)
	defer hm.Stop()

	var runs atomic.Int32
	hm.RegisterCheck(&HealthCheck{
		Name:     "remotelookup_http_late",
		Interval: 10 * time.Millisecond,
		Check: func(context.Context) error {
			runs.Add(1)
			return errors.New("lookup service down")
		},
	})

	deadline := time.Now().Add(2 * time.Second)
	for !hm.IsUnhealthy("remotelookup_http_late") {
		if time.Now().After(deadline) {
			t.Fatalf("check registered after Start: %d runs, status %v; want it run and reported unhealthy", runs.Load(), hm.GetAllStatuses()["remotelookup_http_late"])
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestReregisteredCheckReplacesTheRunningOne: registering a check under a name that is
// already running replaces it; the old check stops instead of running alongside.
func TestReregisteredCheckReplacesTheRunningOne(t *testing.T) {
	hm := NewHealthMonitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hm.Start(ctx)
	defer hm.Stop()

	var oldRuns, newRuns atomic.Int32
	hm.RegisterCheck(&HealthCheck{Name: "dup", Interval: 5 * time.Millisecond, Check: func(context.Context) error {
		oldRuns.Add(1)
		return nil
	}})
	hm.RegisterCheck(&HealthCheck{Name: "dup", Interval: 5 * time.Millisecond, Check: func(context.Context) error {
		newRuns.Add(1)
		return nil
	}})

	deadline := time.Now().Add(2 * time.Second)
	for newRuns.Load() < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("the replacing check ran %d times, want it running", newRuns.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	before := oldRuns.Load()
	time.Sleep(50 * time.Millisecond)
	if after := oldRuns.Load(); after > before+1 { // at most one run already in flight
		t.Errorf("the replaced check kept running: %d runs, then %d", before, after)
	}
}

// TestReplacedCheckInFlightIsCancelledAndDiscarded: a check that is mid-run when its
// name is registered again must be cancelled, and its late outcome must not be
// published under the name the replacement now owns (status callbacks feed the
// health_status row and share the metric series).
func TestReplacedCheckInFlightIsCancelledAndDiscarded(t *testing.T) {
	hm := NewHealthMonitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hm.Start(ctx)
	defer hm.Stop()

	var mu sync.Mutex
	var published []ComponentStatus
	hm.AddStatusCallback(func(name string, status ComponentStatus) {
		if name == "dup" {
			mu.Lock()
			published = append(published, status)
			mu.Unlock()
		}
	})

	started := make(chan struct{})
	var once sync.Once
	var cancelled atomic.Bool
	hm.RegisterCheck(&HealthCheck{Name: "dup", Interval: 5 * time.Millisecond, Timeout: 5 * time.Second, Check: func(ctx context.Context) error {
		once.Do(func() { close(started) })
		select {
		case <-ctx.Done():
			cancelled.Store(true)
		case <-time.After(300 * time.Millisecond):
		}
		return errors.New("replaced check failed")
	}})
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("the first check never ran")
	}

	// The replacement never runs during the test.
	hm.RegisterCheck(&HealthCheck{Name: "dup", Interval: time.Hour, Check: func(context.Context) error { return nil }})

	deadline := time.Now().Add(time.Second)
	for !cancelled.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // status callbacks run on their own goroutines

	if !cancelled.Load() {
		t.Error("the in-flight run of the replaced check was not cancelled")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(published) > 0 {
		t.Errorf("the replaced check published %v under the name its replacement owns", published)
	}
	if status, _ := hm.GetCheckStatus("dup"); status != StatusHealthy {
		t.Errorf("status of the replacement = %q, want %q", status, StatusHealthy)
	}
}
