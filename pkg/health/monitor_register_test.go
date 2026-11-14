package health

import (
	"context"
	"errors"
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
