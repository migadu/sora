package health

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/storage"
	"github.com/minio/minio-go/v7"
)

// HealthIntegration manages health monitoring for the Sora server
type HealthIntegration struct {
	monitor    *HealthMonitor
	database   *resilient.ResilientDatabase
	hostname   string
	relayQueue RelayQueueStatsProvider // For including stats in metadata
}

func NewHealthIntegration(database *resilient.ResilientDatabase) *HealthIntegration {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	return &HealthIntegration{
		monitor:  NewHealthMonitor(),
		database: database,
		hostname: hostname,
	}
}

func (hi *HealthIntegration) Start(ctx context.Context) {
	// Register standard health checks
	hi.registerStandardChecks()

	// Start the health monitor
	hi.monitor.Start(ctx)

	// Register callback to store health data in database
	hi.monitor.AddStatusCallback(hi.storeHealthStatus)
}

func (hi *HealthIntegration) Stop() {
	hi.monitor.Stop()
}

func (hi *HealthIntegration) GetMonitor() *HealthMonitor {
	return hi.monitor
}

func (hi *HealthIntegration) registerStandardChecks() {
	// Database health check
	dbCheck := &HealthCheck{
		Name:     "database",
		Interval: 30 * time.Second,
		Timeout:  10 * time.Second,
		Critical: true,
		Check: func(ctx context.Context) error {
			// Simple ping to verify database connectivity
			return hi.database.GetDatabase().WritePool.Ping(ctx)
		},
	}
	hi.monitor.RegisterCheck(dbCheck)

	// Database read pool health check
	dbReadCheck := &HealthCheck{
		Name:     "database_read_pool",
		Interval: 30 * time.Second,
		Timeout:  10 * time.Second,
		Critical: false,
		Check: func(ctx context.Context) error {
			return hi.database.GetDatabase().ReadPool.Ping(ctx)
		},
	}
	hi.monitor.RegisterCheck(dbReadCheck)
}

func (hi *HealthIntegration) RegisterS3Check(s3storage *storage.S3Storage) {
	s3Check := &HealthCheck{
		Name:     "s3_storage",
		Interval: 60 * time.Second,
		Timeout:  15 * time.Second,
		Critical: true,
		Check: func(ctx context.Context) error {
			// Test S3 connectivity by attempting to list objects
			objectCh := s3storage.Client.ListObjects(ctx, s3storage.BucketName, minio.ListObjectsOptions{MaxKeys: 1})
			select {
			case obj, ok := <-objectCh:
				if !ok {
					// Channel closed without error means bucket is accessible but empty - this is OK
					return nil
				}
				if obj.Err != nil {
					return fmt.Errorf("S3 list objects failed: %w", obj.Err)
				}
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		},
	}
	hi.monitor.RegisterCheck(s3Check)
}

func (hi *HealthIntegration) RegisterCircuitBreakerCheck(name string, breaker *circuitbreaker.CircuitBreaker) {
	cbCheck := &HealthCheck{
		Name:     fmt.Sprintf("circuit_breaker_%s", name),
		Interval: 15 * time.Second,
		Timeout:  5 * time.Second,
		Critical: false,
		Check: func(ctx context.Context) error {
			state := breaker.State()
			counts := breaker.Counts()

			// Store circuit breaker state in metadata but don't fail the check
			// The actual health will be determined by failure rates
			if state == circuitbreaker.StateOpen {
				return fmt.Errorf("circuit breaker is open (requests: %d, failures: %d)",
					counts.Requests, counts.TotalFailures)
			}

			if counts.Requests > 0 {
				failureRate := float64(counts.TotalFailures) / float64(counts.Requests)
				if failureRate > 0.5 {
					return fmt.Errorf("high failure rate %.2f%% (requests: %d, failures: %d)",
						failureRate*100, counts.Requests, counts.TotalFailures)
				}
			}

			return nil
		},
	}
	hi.monitor.RegisterCheck(cbCheck)
}

func (hi *HealthIntegration) RegisterCustomCheck(check *HealthCheck) {
	hi.monitor.RegisterCheck(check)
}

// RelayQueueStatsProvider interface for relay queue statistics
type RelayQueueStatsProvider interface {
	GetStats() (pending, processing, failed int, err error)
}

// RegisterRelayQueueCheck registers a health check for the relay queue
func (hi *HealthIntegration) RegisterRelayQueueCheck(relayQueue RelayQueueStatsProvider) {
	// Store the relay queue reference for use in storeHealthStatus
	hi.relayQueue = relayQueue

	relayQueueCheck := &HealthCheck{
		Name:     "relay_queue",
		Interval: 60 * time.Second,
		Timeout:  5 * time.Second,
		Critical: false, // Not critical since relay is for async delivery
		Enabled:  true,
		Check: func(ctx context.Context) error {
			pending, processing, failed, err := relayQueue.GetStats()
			if err != nil {
				return fmt.Errorf("failed to get relay queue stats: %w", err)
			}

			// Check if failed count is excessive (more than 100 failed messages)
			if failed > 100 {
				return fmt.Errorf("high number of failed messages: %d (pending: %d, processing: %d)", failed, pending, processing)
			}

			// Check if processing queue is backed up (more than 1000 pending)
			if pending > 1000 {
				return fmt.Errorf("relay queue backed up: %d pending messages (processing: %d, failed: %d)", pending, processing, failed)
			}

			return nil
		},
	}
	hi.monitor.RegisterCheck(relayQueueCheck)
}

// PrelookupHealthChecker interface for prelookup clients that support health checks
type PrelookupHealthChecker interface {
	HealthCheck(ctx context.Context) error
}

// PrelookupWithCircuitBreaker interface for prelookup clients with circuit breaker
type PrelookupWithCircuitBreaker interface {
	PrelookupHealthChecker
	GetCircuitBreaker() *circuitbreaker.CircuitBreaker
}

// RegisterPrelookupCheck registers a health check for the prelookup HTTP endpoint
// If the client has a circuit breaker, it will also register a circuit breaker check
func (hi *HealthIntegration) RegisterPrelookupCheck(prelookupClient PrelookupHealthChecker, serverName string) {
	checkName := "prelookup_http"
	if serverName != "" {
		checkName = fmt.Sprintf("prelookup_http_%s", serverName)
	}

	prelookupCheck := &HealthCheck{
		Name:     checkName,
		Interval: 30 * time.Second,
		Timeout:  10 * time.Second,
		Critical: false, // Not critical since prelookup has fallback mode
		Check:    prelookupClient.HealthCheck,
	}
	hi.monitor.RegisterCheck(prelookupCheck)

	// If the client has a circuit breaker, register it too
	if clientWithBreaker, ok := prelookupClient.(PrelookupWithCircuitBreaker); ok {
		if breaker := clientWithBreaker.GetCircuitBreaker(); breaker != nil {
			cbName := "prelookup_http_circuit_breaker"
			if serverName != "" {
				cbName = fmt.Sprintf("prelookup_http_circuit_breaker_%s", serverName)
			}
			hi.RegisterCircuitBreakerCheck(cbName, breaker)
		}
	}
}

func (hi *HealthIntegration) storeHealthStatus(componentName string, status ComponentStatus) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get the health check details with proper locking
	hi.monitor.mu.RLock()
	check, exists := hi.monitor.checks[componentName]
	hi.monitor.mu.RUnlock()

	if !exists {
		return
	}

	// Read check fields with proper locking
	check.mu.RLock()
	interval := check.Interval
	critical := check.Critical
	enabled := check.Enabled
	lastError := check.LastError
	checkCount := check.CheckCount
	failCount := check.FailCount
	check.mu.RUnlock()

	// Create metadata with additional information
	metadata := make(map[string]interface{})
	metadata["interval"] = interval.String()
	metadata["critical"] = critical
	metadata["enabled"] = enabled

	// Add relay queue statistics to metadata if this is the relay_queue component
	if componentName == "relay_queue" && hi.relayQueue != nil {
		pending, processing, failed, err := hi.relayQueue.GetStats()
		if err == nil {
			metadata["pending"] = pending
			metadata["processing"] = processing
			metadata["failed"] = failed
			metadata["total"] = pending + processing + failed
		}
	}

	// Convert health status to db status type
	var dbStatus db.ComponentStatus
	switch status {
	case StatusHealthy:
		dbStatus = db.StatusHealthy
	case StatusDegraded:
		dbStatus = db.StatusDegraded
	case StatusUnhealthy:
		dbStatus = db.StatusUnhealthy
	case StatusUnreachable:
		dbStatus = db.StatusUnreachable
	default:
		dbStatus = db.StatusUnreachable
	}

	// Store in database
	err := hi.database.StoreHealthStatusWithRetry(
		ctx,
		hi.hostname,
		componentName,
		dbStatus,
		lastError,
		checkCount,
		failCount,
		metadata,
	)

	if err != nil {
		logger.Errorf("Failed to store health status for %s: %v", componentName, err)
	}
}

// GetCurrentHealthStatus returns the current health status for all components
func (hi *HealthIntegration) GetCurrentHealthStatus() map[string]ComponentStatus {
	return hi.monitor.GetAllStatuses()
}

// GetOverallStatus returns the overall system health status
func (hi *HealthIntegration) GetOverallStatus() ComponentStatus {
	return hi.monitor.GetOverallStatus()
}

// IsHealthy returns true if the overall system is healthy
func (hi *HealthIntegration) IsHealthy() bool {
	return hi.monitor.GetOverallStatus() == StatusHealthy
}

// IsDegraded returns true if the system is in a degraded state
func (hi *HealthIntegration) IsDegraded() bool {
	status := hi.monitor.GetOverallStatus()
	return status == StatusDegraded
}

// IsUnhealthy returns true if the system is unhealthy
func (hi *HealthIntegration) IsUnhealthy() bool {
	status := hi.monitor.GetOverallStatus()
	return status == StatusUnhealthy || status == StatusUnreachable
}
