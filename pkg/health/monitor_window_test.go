package health

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestSustainedOutageIsReportedUnhealthy drives the real registration +
// performCheck path (no re-implementation of the failure-rate math) through a
// long healthy lifetime, then a total, continuous outage.
//
// The defect under test (pkg/health/monitor.go:157):
//
//	failureRate := float64(check.FailCount) / float64(check.CheckCount)
//
// Both counters are lifetime-cumulative with no sliding window, so the ratio
// can only cross the 0.5 unhealthy threshold after the process has accumulated
// as many failures as it ever had successes. On a long-lived server the
// component reports "degraded" essentially forever during a hard outage.
func TestSustainedOutageIsReportedUnhealthy(t *testing.T) {
	const (
		healthyChecks   = 1000 // ~4h10m of uptime at a 15s interval
		outageChecks    = 240  // 1 full hour of *every single check failing*
		checkInterval   = 15 * time.Second
		componentName   = "database"
		errTotalOutage  = "connection refused: total outage"
		unhealthyStatus = StatusUnhealthy
	)

	var failing atomic.Bool

	check := &HealthCheck{
		Name:     componentName,
		Critical: true,
		// Long interval so the monitor's own goroutine never fires; the test
		// drives performCheck deterministically.
		Interval: time.Hour,
		Timeout:  5 * time.Second,
		Check: func(ctx context.Context) error {
			if failing.Load() {
				return errors.New(errTotalOutage)
			}
			return nil
		},
	}

	hm := NewHealthMonitor()
	hm.RegisterCheck(check)

	// Start() is required: performCheck derives its per-check context from
	// hm.ctx. Started with a long interval, the background ticker never fires
	// during the test.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hm.Start(ctx)
	defer hm.Stop()

	// Phase 1: a long, healthy life.
	for i := 0; i < healthyChecks; i++ {
		hm.performCheck(check)
	}
	if status, _ := hm.GetCheckStatus(componentName); status != StatusHealthy {
		t.Fatalf("setup: after %d successful checks status = %q, want %q",
			healthyChecks, status, StatusHealthy)
	}

	// Phase 2: the backend dies completely. Every subsequent check fails.
	failing.Store(true)
	for i := 0; i < outageChecks; i++ {
		hm.performCheck(check)
	}

	status, ok := hm.GetCheckStatus(componentName)
	if !ok {
		t.Fatalf("check %q not registered", componentName)
	}

	check.mu.RLock()
	failCount, checkCount := check.FailCount, check.CheckCount
	check.mu.RUnlock()
	rate := float64(failCount) / float64(checkCount)

	overall := hm.GetOverallStatus()

	if status != unhealthyStatus {
		t.Errorf(
			"component %q reports %q after %d CONSECUTIVE failed checks (%v of continuous total outage);\n"+
				"want %q.\n"+
				"  cumulative counters: FailCount=%d CheckCount=%d -> lifetime failureRate=%.4f (threshold 0.5)\n"+
				"  overall system status: %q\n"+
				"  monitor.go:157 divides lifetime FailCount by lifetime CheckCount with no sliding window,\n"+
				"  so this component needs %d more consecutive failures (%v of downtime) before it is\n"+
				"  ever called unhealthy.",
			componentName, status, outageChecks, time.Duration(outageChecks)*checkInterval,
			unhealthyStatus,
			failCount, checkCount, rate,
			overall,
			healthyChecks-outageChecks, time.Duration(healthyChecks-outageChecks)*checkInterval,
		)
	}

	if overall != StatusUnhealthy {
		t.Errorf("overall system status = %q after a total outage of the critical %q component, want %q",
			overall, componentName, StatusUnhealthy)
	}
}

// newFailingCheck registers a critical check whose outcome the caller toggles.
// The interval is long enough that the monitor's own ticker never fires; the
// tests drive performCheck directly.
func newFailingCheck(t *testing.T, name string, failing *atomic.Bool) (*HealthMonitor, *HealthCheck) {
	t.Helper()

	check := &HealthCheck{
		Name:     name,
		Critical: true,
		Interval: time.Hour,
		Timeout:  5 * time.Second,
		Check: func(ctx context.Context) error {
			if failing.Load() {
				return errors.New("connection refused: total outage")
			}
			return nil
		},
	}

	hm := NewHealthMonitor()
	hm.RegisterCheck(check)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	hm.Start(ctx)
	t.Cleanup(hm.Stop)

	return hm, check
}

// TestBootTimeOutageIsReportedUnhealthyImmediately is the boot-time inverse of
// TestSustainedOutageIsReportedUnhealthy: a component that is hard-down from its
// very first check has no healthy history to debounce against, so the
// consecutive-failure threshold must not hold it at "degraded".
//
// pkg/degradation/strategy.go:344 escalates an unhealthy "database" to
// LevelEmergency, while a single degraded component maps to LevelMinor
// (strategy.go:342), which activates no load-shedding strategy at all
// (shouldActivateStrategy, strategy.go:395). Every check interval spent at
// "degraded" is an interval where the process keeps accepting work it cannot
// serve.
func TestBootTimeOutageIsReportedUnhealthyImmediately(t *testing.T) {
	const componentName = "database"

	var failing atomic.Bool
	failing.Store(true)

	hm, check := newFailingCheck(t, componentName, &failing)

	// Every check from the very first one fails: the component has never worked.
	for i := 1; i <= unhealthyConsecutiveFailures; i++ {
		hm.performCheck(check)

		status, _ := hm.GetCheckStatus(componentName)
		overall := hm.GetOverallStatus()

		if status != StatusUnhealthy {
			t.Errorf(
				"component %q reports %q after failed check #%d, with zero successful checks ever; want %q.\n"+
					"  the component has never once succeeded, so there is no healthy baseline to call this a blip\n"+
					"  overall system status: %q (degradation level for a lone degraded component is minor, which sheds no load)",
				componentName, status, i, StatusUnhealthy, overall)
		}
		if overall != StatusUnhealthy {
			t.Errorf("overall system status = %q after failed check #%d of the critical %q component, want %q",
				overall, i, componentName, StatusUnhealthy)
		}
		if !hm.IsUnhealthy(componentName) {
			t.Errorf("IsUnhealthy(%q) = false after failed check #%d; pkg/degradation only reaches LevelEmergency when this is true",
				componentName, i)
		}
	}
}

// TestBlipAfterHealthyHistoryDoesNotEscalate guards the improvement the
// consecutive-failure threshold bought: once a component has proven it works,
// isolated failures must stay "degraded" until the evidence is sustained.
func TestBlipAfterHealthyHistoryDoesNotEscalate(t *testing.T) {
	const componentName = "database"

	var failing atomic.Bool
	hm, check := newFailingCheck(t, componentName, &failing)

	for i := 0; i < 50; i++ {
		hm.performCheck(check)
	}
	if status, _ := hm.GetCheckStatus(componentName); status != StatusHealthy {
		t.Fatalf("setup: status = %q after 50 successful checks, want %q", status, StatusHealthy)
	}

	// A single blip, then immediate recovery.
	failing.Store(true)
	hm.performCheck(check)
	if status, _ := hm.GetCheckStatus(componentName); status != StatusDegraded {
		t.Errorf("status = %q after ONE failed check following a long healthy run, want %q",
			status, StatusDegraded)
	}

	failing.Store(false)
	hm.performCheck(check)
	if status, _ := hm.GetCheckStatus(componentName); status != StatusHealthy {
		t.Errorf("status = %q after the component recovered from a single blip, want %q",
			status, StatusHealthy)
	}

	// Two consecutive failures are still not enough evidence.
	failing.Store(true)
	hm.performCheck(check)
	hm.performCheck(check)
	if status, _ := hm.GetCheckStatus(componentName); status != StatusDegraded {
		t.Errorf("status = %q after %d consecutive failures following a healthy run, want %q",
			status, unhealthyConsecutiveFailures-1, StatusDegraded)
	}

	hm.performCheck(check)
	if status, _ := hm.GetCheckStatus(componentName); status != StatusUnhealthy {
		t.Errorf("status = %q after %d consecutive failures, want %q",
			status, unhealthyConsecutiveFailures, StatusUnhealthy)
	}
}

// TestRecoveryAfterBootTimeOutageRestoresDebounce checks that escalating a
// never-successful component is a one-way door: once it works, it earns the
// same debounce every other component gets.
func TestRecoveryAfterBootTimeOutageRestoresDebounce(t *testing.T) {
	const componentName = "s3_storage"

	var failing atomic.Bool
	failing.Store(true)

	hm, check := newFailingCheck(t, componentName, &failing)

	hm.performCheck(check)
	if status, _ := hm.GetCheckStatus(componentName); status != StatusUnhealthy {
		t.Fatalf("setup: status = %q on a component that never succeeded, want %q", status, StatusUnhealthy)
	}

	failing.Store(false)
	hm.performCheck(check)
	if status, _ := hm.GetCheckStatus(componentName); status != StatusHealthy {
		t.Fatalf("status = %q after the component finally came up, want %q", status, StatusHealthy)
	}
	if overall := hm.GetOverallStatus(); overall != StatusHealthy {
		t.Errorf("overall system status = %q after recovery, want %q", overall, StatusHealthy)
	}

	failing.Store(true)
	hm.performCheck(check)
	if status, _ := hm.GetCheckStatus(componentName); status != StatusDegraded {
		t.Errorf("status = %q after a single failure following recovery, want %q; a component that has\n"+
			"  proven it works must be debounced like any other", status, StatusDegraded)
	}
}
