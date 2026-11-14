package health

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/metrics"
)

type ComponentStatus string

const (
	StatusHealthy     ComponentStatus = "healthy"
	StatusDegraded    ComponentStatus = "degraded"
	StatusUnhealthy   ComponentStatus = "unhealthy"
	StatusUnreachable ComponentStatus = "unreachable"
)

const (
	// Consecutive failed checks that mark a component unhealthy, matching the
	// backend threshold used by the proxy connection manager.
	unhealthyConsecutiveFailures = 3
	// Failure rate over the recent window that marks a component unhealthy when
	// failures are intermittent rather than consecutive.
	unhealthyFailureRate = 0.5
	recentOutcomeWindow  = 10
)

// failureWindow is a ring of the most recent check outcomes.
type failureWindow struct {
	outcomes [recentOutcomeWindow]bool
	next     int
	size     int
	failures int
}

func (w *failureWindow) record(failed bool) {
	if w.outcomes[w.next] {
		w.failures--
	}
	w.outcomes[w.next] = failed
	if failed {
		w.failures++
	}
	w.next = (w.next + 1) % len(w.outcomes)
	if w.size < len(w.outcomes) {
		w.size++
	}
}

func (w *failureWindow) rate() float64 {
	if w.size == 0 {
		return 0
	}
	return float64(w.failures) / float64(w.size)
}

// sustained reports whether a full window fails at or above rate. A partial
// window never qualifies; early failures are covered by the consecutive
// failure threshold instead.
func (w *failureWindow) sustained(rate float64) bool {
	return w.size == len(w.outcomes) && w.rate() >= rate
}

type HealthCheck struct {
	Name     string
	Check    func(ctx context.Context) error
	Interval time.Duration
	Timeout  time.Duration
	Critical bool // If true, failure affects overall system health
	Enabled  bool

	// Fields below are protected by mu
	mu         sync.RWMutex
	LastCheck  time.Time
	LastError  error
	Status     ComponentStatus
	CheckCount int
	FailCount  int

	// CheckCount and FailCount are lifetime totals reported to operators; the
	// status is derived from these recent-outcome fields instead.
	consecutiveFails int
	recent           failureWindow
	everSucceeded    bool

	// stop ends the goroutine running this check. Set and called under HealthMonitor.mu.
	stop context.CancelFunc
}

type HealthMonitor struct {
	checks          map[string]*HealthCheck
	mu              sync.RWMutex
	overallStatus   ComponentStatus
	ctx             context.Context
	cancel          context.CancelFunc
	statusCallbacks []func(name string, status ComponentStatus)
}

func NewHealthMonitor() *HealthMonitor {
	return &HealthMonitor{
		checks:          make(map[string]*HealthCheck),
		overallStatus:   StatusHealthy,
		statusCallbacks: make([]func(string, ComponentStatus), 0),
	}
}

// RegisterCheck adds a check, replacing any check of the same name. On a running
// monitor the check starts at once: the proxies register theirs (remote lookup) while
// they start, after Start.
func (hm *HealthMonitor) RegisterCheck(check *HealthCheck) {
	if check.Interval == 0 {
		check.Interval = 30 * time.Second
	}
	if check.Timeout == 0 {
		check.Timeout = 10 * time.Second
	}
	check.Status = StatusHealthy
	check.Enabled = true

	hm.mu.Lock()
	defer hm.mu.Unlock()
	if old, ok := hm.checks[check.Name]; ok && old.stop != nil {
		old.stop()
	}
	hm.checks[check.Name] = check
	if hm.ctx != nil {
		hm.startCheckLocked(check)
	}
}

func (hm *HealthMonitor) AddStatusCallback(callback func(name string, status ComponentStatus)) {
	hm.mu.Lock()
	hm.statusCallbacks = append(hm.statusCallbacks, callback)
	hm.mu.Unlock()
}

func (hm *HealthMonitor) Start(ctx context.Context) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.ctx, hm.cancel = context.WithCancel(ctx)
	for _, check := range hm.checks {
		hm.startCheckLocked(check)
	}
}

// startCheckLocked runs check on its own goroutine until the monitor stops or the
// check is replaced. hm.mu must be held.
func (hm *HealthMonitor) startCheckLocked(check *HealthCheck) {
	if !check.Enabled {
		return
	}
	ctx, cancel := context.WithCancel(hm.ctx)
	check.stop = cancel
	go hm.runHealthCheck(ctx, check)
}

func (hm *HealthMonitor) Stop() {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	if hm.cancel != nil {
		hm.cancel()
	}
}

func (hm *HealthMonitor) runHealthCheck(ctx context.Context, check *HealthCheck) {
	ticker := time.NewTicker(check.Interval)
	defer ticker.Stop()

	logger.Info("Health: Started monitoring", "check", check.Name, "interval", check.Interval)

	// Don't perform the first check immediately - wait for the first ticker interval
	// to allow the application to fully initialize and avoid context cancellation issues
	for {
		select {
		case <-ctx.Done():
			logger.Info("Health: Monitoring stopped due to context cancellation", "check", check.Name)
			return
		case <-ticker.C:
			hm.performCheck(ctx, check)
		}
	}
}

// performCheck runs check once under runCtx, the context the check runs under. A run
// whose runCtx ends meanwhile (the check was replaced, or the monitor stopped) is
// discarded: the name may belong to a replacement by then, and "context canceled"
// says nothing about the component.
func (hm *HealthMonitor) performCheck(runCtx context.Context, check *HealthCheck) {
	ctx, cancel := context.WithTimeout(runCtx, check.Timeout)
	defer cancel()

	// Time the health check
	startTime := time.Now()

	// Only the supplied check runs under recovery; a panic follows the same
	// cancellation and publication rules as an ordinary result.
	err, panicked := func() (err error, panicked bool) {
		defer func() {
			if r := recover(); r != nil {
				err, panicked = fmt.Errorf("panic: %v", r), true
			}
		}()
		return check.Check(ctx), false
	}()
	duration := time.Since(startTime).Seconds()

	// Registration and publication share the monitor lock. Acquire locks in
	// the same order as updateOverallStatus, and check cancellation after both:
	// this run may have been canceled while it waited to publish.
	hm.mu.Lock()
	check.mu.Lock()
	if runCtx.Err() != nil || hm.checks[check.Name] != check {
		check.mu.Unlock()
		hm.mu.Unlock()
		return
	}

	// Record duration metric
	metrics.ComponentHealthCheckDuration.WithLabelValues(check.Name, "").Observe(duration)

	// Now update the check state with proper locking
	check.CheckCount++
	check.LastCheck = time.Now()
	check.recent.record(err != nil)
	previousStatus := check.Status
	isFirstCheck := check.CheckCount == 1

	if err != nil {
		check.FailCount++
		check.consecutiveFails++
		check.LastError = err

		// A run of failures, or a persistently failing window, means the
		// component is down. Anything less is a blip. A component that has
		// never once succeeded has no healthy history to call a blip against,
		// so it escalates on its first failure.
		if panicked || !check.everSucceeded || check.consecutiveFails >= unhealthyConsecutiveFailures || check.recent.sustained(unhealthyFailureRate) {
			check.Status = StatusUnhealthy
		} else {
			check.Status = StatusDegraded
		}

		logger.Warn("Health check failed", "check", check.Name, "error", err, "status", check.Status, "failure_rate", check.recent.rate(), "consecutive_failures", check.consecutiveFails)
		if panicked {
			logger.Error("Health: PANIC during check for component", "component", check.Name, "error", err)
		}
	} else {
		check.LastError = nil
		check.consecutiveFails = 0
		check.everSucceeded = true
		// A successful check clears the state, but recent failures hold the
		// component degraded until they age out of the window.
		if check.recent.sustained(unhealthyFailureRate) {
			check.Status = StatusDegraded
		} else {
			check.Status = StatusHealthy
		}
	}

	currentStatus := check.Status
	check.mu.Unlock()

	// Record health check metrics
	metrics.ComponentHealthChecks.WithLabelValues(check.Name, "", string(currentStatus)).Inc()

	// Update health status gauge (0=unreachable, 1=unhealthy, 2=degraded, 3=healthy)
	var statusValue float64
	switch currentStatus {
	case StatusHealthy:
		statusValue = 3
	case StatusDegraded:
		statusValue = 2
	case StatusUnhealthy:
		statusValue = 1
	case StatusUnreachable:
		statusValue = 0
	}
	metrics.ComponentHealthStatus.WithLabelValues(check.Name, "").Set(statusValue)

	if previousStatus != currentStatus || isFirstCheck {
		if isFirstCheck {
			logger.Info("Health: Check initialized", "check", check.Name, "status", currentStatus)
		} else {
			logger.Info("Health: Check status changed", "check", check.Name, "from", previousStatus, "to", currentStatus)
		}
		hm.notifyStatusChangeLocked(check.Name, currentStatus)
	}
	hm.mu.Unlock()

	hm.updateOverallStatus()
}

// notifyStatusChangeLocked dispatches an accepted result before registration may
// replace it. Callbacks run asynchronously, so they can reenter the monitor.
// hm.mu must be held; no callback is invoked synchronously under it.
func (hm *HealthMonitor) notifyStatusChangeLocked(name string, status ComponentStatus) {
	for _, callback := range hm.statusCallbacks {
		go callback(name, status)
	}
}

func (hm *HealthMonitor) updateOverallStatus() {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	var criticalUnhealthy, criticalDegraded bool
	var anyDegraded bool

	for _, check := range hm.checks {
		check.mu.RLock()
		status := check.Status
		critical := check.Critical
		check.mu.RUnlock()

		if critical {
			switch status {
			case StatusUnhealthy, StatusUnreachable:
				criticalUnhealthy = true
			case StatusDegraded:
				criticalDegraded = true
			}
		}

		if status == StatusDegraded {
			anyDegraded = true
		}
	}

	previousStatus := hm.overallStatus

	switch {
	case criticalUnhealthy:
		hm.overallStatus = StatusUnhealthy
	case criticalDegraded || anyDegraded:
		hm.overallStatus = StatusDegraded
	default:
		hm.overallStatus = StatusHealthy
	}

	if previousStatus != hm.overallStatus {
		logger.Info("Health: Overall system status changed", "from", previousStatus, "to", hm.overallStatus)
	}
}

func (hm *HealthMonitor) GetOverallStatus() ComponentStatus {
	hm.mu.RLock()
	defer hm.mu.RUnlock()
	return hm.overallStatus
}

func (hm *HealthMonitor) GetCheckStatus(name string) (ComponentStatus, bool) {
	hm.mu.RLock()
	check, exists := hm.checks[name]
	hm.mu.RUnlock()

	if !exists {
		return StatusUnreachable, false
	}

	check.mu.RLock()
	status := check.Status
	check.mu.RUnlock()

	return status, true
}

func (hm *HealthMonitor) GetAllStatuses() map[string]ComponentStatus {
	hm.mu.RLock()
	checks := make(map[string]*HealthCheck)
	for name, check := range hm.checks {
		checks[name] = check
	}
	hm.mu.RUnlock()

	statuses := make(map[string]ComponentStatus)
	for name, check := range checks {
		check.mu.RLock()
		statuses[name] = check.Status
		check.mu.RUnlock()
	}

	return statuses
}

func (hm *HealthMonitor) IsHealthy(name string) bool {
	status, exists := hm.GetCheckStatus(name)
	return exists && status == StatusHealthy
}

func (hm *HealthMonitor) IsDegraded(name string) bool {
	status, exists := hm.GetCheckStatus(name)
	return exists && status == StatusDegraded
}

func (hm *HealthMonitor) IsUnhealthy(name string) bool {
	status, exists := hm.GetCheckStatus(name)
	return exists && (status == StatusUnhealthy || status == StatusUnreachable)
}

func CreateDatabaseHealthCheck() *HealthCheck {
	return &HealthCheck{
		Name:     "database",
		Interval: 15 * time.Second,
		Timeout:  5 * time.Second,
		Critical: true,
		Check: func(ctx context.Context) error {
			// This would be implemented to actually check database connectivity
			// For now, return nil (healthy)
			return nil
		},
	}
}

func CreateS3HealthCheck() *HealthCheck {
	return &HealthCheck{
		Name:     "s3_storage",
		Interval: 30 * time.Second,
		Timeout:  10 * time.Second,
		Critical: true,
		Check: func(ctx context.Context) error {
			// This would be implemented to actually check S3 connectivity
			// For now, return nil (healthy)
			return nil
		},
	}
}

type CircuitBreakerHealthAdapter struct {
	breaker *circuitbreaker.CircuitBreaker
	name    string
}

func NewCircuitBreakerHealthAdapter(breaker *circuitbreaker.CircuitBreaker, name string) *CircuitBreakerHealthAdapter {
	return &CircuitBreakerHealthAdapter{
		breaker: breaker,
		name:    name,
	}
}

func (cb *CircuitBreakerHealthAdapter) GetStatus() ComponentStatus {
	switch cb.breaker.State() {
	case circuitbreaker.StateClosed:
		counts := cb.breaker.Counts()
		if counts.TotalFailures > 0 {
			failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
			if failureRatio > 0.2 {
				return StatusDegraded
			}
		}
		return StatusHealthy
	case circuitbreaker.StateHalfOpen:
		return StatusDegraded
	case circuitbreaker.StateOpen:
		return StatusUnhealthy
	default:
		return StatusUnreachable
	}
}
