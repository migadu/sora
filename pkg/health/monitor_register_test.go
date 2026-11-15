package health

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
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

func TestReplacedCheckPanicIsDiscarded(t *testing.T) {
	hm := NewHealthMonitor()
	hm.Start(context.Background())
	defer hm.Stop()
	name := t.Name()
	started, returned := make(chan struct{}), make(chan struct{})
	published := make(chan ComponentStatus, 1)
	hm.AddStatusCallback(func(got string, status ComponentStatus) {
		if got == name {
			published <- status
		}
	})
	old := &HealthCheck{Name: name, Interval: time.Millisecond, Check: func(ctx context.Context) error {
		close(started)
		defer close(returned)
		<-ctx.Done()
		panic("replaced check unwinding")
	}}
	hm.RegisterCheck(old)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("old check never started")
	}
	hm.RegisterCheck(&HealthCheck{Name: name, Interval: time.Hour, Check: func(context.Context) error { return nil }})
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("replacement did not cancel the old check")
	}
	select {
	case status := <-published:
		t.Fatalf("replaced check published %s after panicking during cancellation", status)
	case <-time.After(50 * time.Millisecond):
	}
	old.mu.RLock()
	defer old.mu.RUnlock()
	if old.Status != StatusHealthy || old.LastError != nil || old.CheckCount != 0 {
		t.Errorf("canceled panic changed old state: status=%s, error=%v, count=%d", old.Status, old.LastError, old.CheckCount)
	}
}

func TestCheckCancelledWhileWaitingToPublishIsDiscarded(t *testing.T) {
	hm := NewHealthMonitor()
	name := t.Name()
	returned := make(chan struct{})
	check := &HealthCheck{Name: name, Check: func(context.Context) error {
		close(returned)
		return errors.New("late failure")
	}}
	hm.RegisterCheck(check)
	metrics.ComponentHealthStatus.WithLabelValues(name, hm.hostname).Set(3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	// Hold the state lock while the run completes, then cancel before allowing
	// publication. Checking cancellation only before taking this lock is too early.
	check.mu.Lock()
	go func() { defer close(done); hm.performCheck(ctx, check) }()
	select {
	case <-returned:
	case <-time.After(time.Second):
		check.mu.Unlock()
		t.Fatal("check never completed")
	}
	time.Sleep(20 * time.Millisecond)
	cancel()
	check.mu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("check did not finish")
	}
	check.mu.RLock()
	defer check.mu.RUnlock()
	if check.CheckCount != 0 || check.Status != StatusHealthy {
		t.Errorf("canceled check published count=%d status=%s", check.CheckCount, check.Status)
	}
	if got := testutil.ToFloat64(metrics.ComponentHealthStatus.WithLabelValues(name, hm.hostname)); got != 3 {
		t.Errorf("canceled check changed gauge to %v, want 3", got)
	}
}

func TestCheckPanicPublishesAndCallbackCanReenter(t *testing.T) {
	hm := NewHealthMonitor()
	name := t.Name()
	check := &HealthCheck{Name: name, Check: func(context.Context) error { panic("active check failed") }}
	hm.RegisterCheck(check)
	done := make(chan ComponentStatus, 1)
	hm.AddStatusCallback(func(got string, status ComponentStatus) {
		if got != name {
			return
		}
		// Both a read and registration from a callback must be able to take
		// the monitor lock without blocking publication forever.
		if current, _ := hm.GetCheckStatus(name); current != status {
			done <- current
			return
		}
		hm.RegisterCheck(&HealthCheck{Name: name, Check: func(context.Context) error { return nil }})
		done <- status
	})
	hm.performCheck(context.Background(), check)
	select {
	case status := <-done:
		if status != StatusUnhealthy {
			t.Errorf("panic published %s, want unhealthy", status)
		}
	case <-time.After(time.Second):
		t.Fatal("callback could not reenter the monitor")
	}
	check.mu.RLock()
	defer check.mu.RUnlock()
	if check.Status != StatusUnhealthy || check.LastError == nil || check.CheckCount != 1 || check.FailCount != 1 {
		t.Errorf("panic outcome: status=%s error=%v count=%d failures=%d", check.Status, check.LastError, check.CheckCount, check.FailCount)
	}
}
