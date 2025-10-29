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
	hm.checks[check.Name] = check
	hm.mu.Unlock()
}

func (hm *HealthMonitor) AddStatusCallback(callback func(name string, status ComponentStatus)) {
	hm.mu.Lock()
	hm.statusCallbacks = append(hm.statusCallbacks, callback)
	hm.mu.Unlock()
}

func (hm *HealthMonitor) Start(ctx context.Context) {
	hm.ctx, hm.cancel = context.WithCancel(ctx)

	hm.mu.RLock()
	for _, check := range hm.checks {
		if check.Enabled {
			go hm.runHealthCheck(check)
		}
	}
	hm.mu.RUnlock()
}

func (hm *HealthMonitor) Stop() {
	if hm.cancel != nil {
		hm.cancel()
	}
}

func (hm *HealthMonitor) runHealthCheck(check *HealthCheck) {
	ticker := time.NewTicker(check.Interval)
	defer ticker.Stop()

	logger.Infof("[HEALTH] Started monitoring '%s' with interval %v", check.Name, check.Interval)

	// Don't perform the first check immediately - wait for the first ticker interval
	// to allow the application to fully initialize and avoid context cancellation issues
	for {
		select {
		case <-hm.ctx.Done():
			logger.Infof("[HEALTH] Monitoring stopped for '%s' due to context cancellation", check.Name)
			return
		case <-ticker.C:
			hm.performCheck(check)
		}
	}
}

func (hm *HealthMonitor) performCheck(check *HealthCheck) {
	// Recover from panics within a health check to prevent the monitor goroutine from crashing.
	defer func() {
		if r := recover(); r != nil {
			// A panic is a critical failure, so we mark the component as unhealthy.
			err := fmt.Errorf("panic: %v", r)
			logger.Errorf("[HEALTH] PANIC during check for component '%s': %v", check.Name, err)

			check.mu.Lock()
			check.Status = StatusUnhealthy
			check.LastError = err
			check.mu.Unlock()

			hm.notifyStatusChange(check.Name, StatusUnhealthy)
			hm.updateOverallStatus()
		}
	}()

	ctx, cancel := context.WithTimeout(hm.ctx, check.Timeout)
	defer cancel()

	// Time the health check
	startTime := time.Now()

	// Perform the actual check first (no lock needed)
	err := check.Check(ctx)

	// Record duration metric
	duration := time.Since(startTime).Seconds()
	metrics.ComponentHealthCheckDuration.WithLabelValues(check.Name, "").Observe(duration)

	// Now update the check state with proper locking
	check.mu.Lock()
	check.CheckCount++
	check.LastCheck = time.Now()
	previousStatus := check.Status
	isFirstCheck := check.CheckCount == 1

	if err != nil {
		check.FailCount++
		check.LastError = err

		failureRate := float64(check.FailCount) / float64(check.CheckCount)

		// If failure rate is high, mark as unhealthy. Otherwise, a single
		// failure will result in a 'degraded' state.
		if failureRate >= 0.5 {
			check.Status = StatusUnhealthy
		} else {
			check.Status = StatusDegraded
		}

		logger.Warnf("[HEALTH] check '%s' failed: %v (status: %s, failure rate: %.2f)",
			check.Name, err, check.Status, failureRate)
	} else {
		check.LastError = nil
		// A successful check transitions the state back to healthy.
		check.Status = StatusHealthy
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
			logger.Infof("[HEALTH] check '%s' initialized: %s", check.Name, currentStatus)
		} else {
			logger.Infof("[HEALTH] check '%s' status changed: %s -> %s", check.Name, previousStatus, currentStatus)
		}
		hm.notifyStatusChange(check.Name, currentStatus)
	}

	hm.updateOverallStatus()
}

func (hm *HealthMonitor) notifyStatusChange(name string, status ComponentStatus) {
	hm.mu.RLock()
	callbacks := make([]func(string, ComponentStatus), len(hm.statusCallbacks))
	copy(callbacks, hm.statusCallbacks)
	hm.mu.RUnlock()

	for _, callback := range callbacks {
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
		logger.Infof("[HEALTH] overall system status changed: %s -> %s", previousStatus, hm.overallStatus)
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
