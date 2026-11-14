package health

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// The health_status row of a component is written by the status callback, and the
// cleaner deletes rows not updated within [cleanup] health_status_retention (30 days by
// default), meant for decommissioned nodes. A component that stays healthy on a running
// node must therefore be reported again now and then, not only on its first check and
// on status changes, or its row disappears and the node reads as unreachable.
func TestStableComponentIsReportedPeriodically(t *testing.T) {
	const checks = 1000 // 8h20m at the default 30s interval

	check := &HealthCheck{
		Name:     "database",
		Interval: time.Hour, // the test drives performCheck itself
		Timeout:  5 * time.Second,
		Check:    func(ctx context.Context) error { return nil },
	}
	hm := NewHealthMonitor()
	hm.RegisterCheck(check)
	var reports atomic.Int64
	hm.AddStatusCallback(func(name string, status ComponentStatus) {
		if name == check.Name && status == StatusHealthy {
			reports.Add(1)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hm.Start(ctx)
	defer hm.Stop()

	for i := 0; i < checks; i++ {
		hm.performCheck(check)
	}

	// Callbacks run in goroutines of their own; give them a moment.
	const atLeast = checks / 100 // once per 100 checks: 50 minutes at 30s
	deadline := time.Now().Add(2 * time.Second)
	for reports.Load() < atLeast && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := reports.Load(); got < atLeast {
		t.Fatalf("a component healthy for %d checks was reported %d time(s), want at least %d", checks, got, atLeast)
	}
}
