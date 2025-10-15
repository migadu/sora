// Package resilient provides resilient database operations with automatic failover and retry.
//
// This package wraps the db package with production-grade resilience features:
//   - Automatic failover between multiple database pools
//   - Circuit breakers to prevent cascading failures
//   - Exponential backoff retry with jitter
//   - Health monitoring and automatic recovery
//   - Connection pooling with read/write separation
//   - Transient error detection and retry
//
// # Architecture
//
// The ResilientDatabase wraps multiple database pools and automatically
// routes operations to healthy backends. If a pool fails, traffic is
// redirected to healthy pools while the failed pool recovers.
//
//	┌─────────────────────┐
//	│ ResilientDatabase   │
//	├─────────────────────┤
//	│ - Failover Manager  │
//	│ - Circuit Breakers  │
//	│ - Retry Logic       │
//	└──────────┬──────────┘
//	           │
//	    ┌──────┴──────┐
//	    │             │
//	┌───▼───┐    ┌───▼───┐
//	│ Pool1 │    │ Pool2 │
//	│ (RW)  │    │ (RW)  │
//	└───────┘    └───────┘
//
// # Usage
//
//	// Create resilient database with failover
//	cfg := &config.DatabaseConfig{
//		Endpoints: []config.DatabaseEndpointConfig{
//			{Hosts: []string{"db1:5432", "db2:5432"}},
//			{Hosts: []string{"db3:5432", "db4:5432"}},
//		},
//		Database: "sora_mail_db",
//	}
//	rdb, err := resilient.NewResilientDatabase(ctx, cfg, true, true)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer rdb.Close()
//
//	// Operations automatically retry on transient failures
//	mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, userID, "INBOX")
//
// # Retry Configuration
//
// Each operation has customized retry settings based on its characteristics:
//   - Read operations: Fast retries, more attempts
//   - Write operations: Slower retries, fewer attempts
//   - Critical operations: No retries (e.g., UID allocation)
//
// # Health Monitoring
//
// Health checks run in the background, marking pools as healthy/unhealthy:
//
//	status := rdb.HealthStatus()
//	if status.Status != "healthy" {
//		log.Printf("Database unhealthy: %s", status.Message)
//	}
//
// # Circuit Breakers
//
// Circuit breakers protect against cascading failures:
//   - Closed: Normal operation
//   - Open: Too many failures, reject immediately
//   - Half-open: Testing recovery
//
// # Transient Error Detection
//
// The package automatically detects and retries transient errors:
//   - Connection errors
//   - Timeout errors
//   - Deadlock errors
//   - Serialization failures
//
// Permanent errors (e.g., constraint violations) are not retried.
package resilient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/retry"
)

// DatabasePool represents a single database connection pool with health tracking
type DatabasePool struct {
	database    *db.Database
	host        string
	isHealthy   atomic.Bool
	lastFailure atomic.Int64 // Unix timestamp
	failCount   atomic.Int64
}

// FailedReplica tracks a read replica that failed to connect at startup
type FailedReplica struct {
	host           string
	endpointConfig *config.DatabaseEndpointConfig
	lastAttempt    time.Time
	attemptCount   int
	mu             sync.Mutex
}

// RuntimeFailoverManager manages multiple database pools and handles failover
type RuntimeFailoverManager struct {
	writePools      []*DatabasePool
	readPools       []*DatabasePool
	failedReplicas  []*FailedReplica // Read replicas that failed at startup
	currentWriteIdx atomic.Int64
	currentReadIdx  atomic.Int64
	config          *config.DatabaseConfig
	healthCheckStop chan struct{}
	healthCheckWg   sync.WaitGroup // Wait for background goroutines to finish
	mu              sync.RWMutex
}

// readPoolsAreDistinct checks if the read pools are a separate set from the write pools.
func (fm *RuntimeFailoverManager) readPoolsAreDistinct() bool {
	// If there are no read pools or no write pools, they can't be distinct.
	if len(fm.readPools) == 0 || len(fm.writePools) == 0 {
		return false
	}
	// Slices are distinct if their first elements' memory addresses are different.
	return &fm.readPools[0] != &fm.writePools[0]
}

type ResilientDatabase struct {
	// Runtime failover support
	failoverManager *RuntimeFailoverManager

	// Circuit breakers (per-operation type)
	queryBreaker *circuitbreaker.CircuitBreaker
	writeBreaker *circuitbreaker.CircuitBreaker

	// Database configuration for timeouts
	config *config.DatabaseConfig
}

func NewResilientDatabase(ctx context.Context, config *config.DatabaseConfig, enableHealthCheck bool, runMigrations bool) (*ResilientDatabase, error) {
	// Create circuit breakers
	querySettings := circuitbreaker.DefaultSettings("database_query")
	querySettings.MaxRequests = 5
	querySettings.Interval = 15 * time.Second
	querySettings.Timeout = 45 * time.Second
	querySettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 8 && failureRatio >= 0.6
	}
	querySettings.OnStateChange = func(name string, from circuitbreaker.State, to circuitbreaker.State) {
		logger.Info("Database query circuit breaker state changed", "component", "RESILIENT-FAILOVER", "name", name, "from", from, "to", to)
	}

	writeSettings := circuitbreaker.DefaultSettings("database_write")
	writeSettings.MaxRequests = 3
	writeSettings.Interval = 10 * time.Second
	writeSettings.Timeout = 30 * time.Second
	writeSettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 5 && failureRatio >= 0.5
	}
	writeSettings.OnStateChange = func(name string, from circuitbreaker.State, to circuitbreaker.State) {
		logger.Info("Database write circuit breaker state changed", "component", "RESILIENT-FAILOVER", "name", name, "from", from, "to", to)
	}

	// Create failover manager
	failoverManager, err := newRuntimeFailoverManager(ctx, config, runMigrations)
	if err != nil {
		return nil, fmt.Errorf("failed to create failover manager: %w", err)
	}

	rdb := &ResilientDatabase{
		failoverManager: failoverManager,
		queryBreaker:    circuitbreaker.NewCircuitBreaker(querySettings),
		writeBreaker:    circuitbreaker.NewCircuitBreaker(writeSettings),
		config:          config,
	}

	// Start background health checking if enabled
	if enableHealthCheck {
		go rdb.startRuntimeHealthChecking(ctx)
	}

	return rdb, nil
}

// timeoutType defines the type of database operation.
type timeoutType int

const (
	timeoutRead timeoutType = iota
	timeoutWrite
	timeoutSearch
	timeoutAuth  // Authentication operations (rate limiting, password verification)
	timeoutAdmin // Administrative operations (user creation, imports, exports)
)

// withTimeout creates a new context with the appropriate timeout.
func (rd *ResilientDatabase) withTimeout(ctx context.Context, opType timeoutType) (context.Context, context.CancelFunc) {
	var timeout time.Duration
	var err error

	// Determine the base timeout from the global config.
	switch opType {
	case timeoutWrite:
		timeout, err = rd.config.GetWriteTimeout()
		if err != nil {
			logger.Warn("Invalid global write_timeout, using default 10s", "error", err)
			timeout = 15 * time.Second
		}
	case timeoutSearch:
		timeout, err = rd.config.GetSearchTimeout()
		if err != nil {
			logger.Warn("Invalid global search_timeout, using default", "error", err)
			timeout = 60 * time.Second
		}
	case timeoutAuth:
		// Auth operations should be fast - use write timeout as base, but shorter
		timeout, err = rd.config.GetWriteTimeout()
		if err != nil {
			logger.Warn("Invalid global write_timeout for auth, using default 10s", "error", err)
			timeout = 10 * time.Second
		} else if timeout > 10*time.Second {
			// Cap auth timeout to be reasonably fast
			timeout = 10 * time.Second
		}
	case timeoutAdmin:
		// Admin operations can be longer (imports, user creation)
		timeout, err = rd.config.GetSearchTimeout() // Use search timeout as base
		if err != nil {
			logger.Warn("Invalid global search_timeout for admin, using default 45s", "error", err)
			timeout = 45 * time.Second
		}
		timeout = time.Duration(float64(timeout) * 0.75) // Admin ops get 75% of search timeout
	default: // timeoutRead
		timeout, err = rd.config.GetQueryTimeout()
		if err != nil {
			logger.Warn("Invalid global query_timeout, using default", "error", err)
			timeout = 30 * time.Second
		}

		// For reads, check for an endpoint-specific override.
		endpointConfig := rd.config.Read
		if endpointConfig == nil {
			endpointConfig = rd.config.Write // Fallback to write if no read config
		}

		if endpointConfig != nil {
			endpointTimeout, endpointErr := endpointConfig.GetQueryTimeout()
			if endpointErr != nil {
				logger.Warn("Invalid endpoint query_timeout, using global/default", "error", endpointErr)
			} else if endpointTimeout > 0 {
				timeout = endpointTimeout // Override with endpoint-specific timeout
			}
		}
	}

	return context.WithTimeout(ctx, timeout)
}

func (rd *ResilientDatabase) GetDatabase() *db.Database {
	return rd.getCurrentDatabase()
}

// isRetryableError checks if an error is transient and the operation can be retried.
// It uses type assertions and error codes for robust checking.
func (rd *ResilientDatabase) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Do not retry if the circuit breaker is open or the context is done.
	if errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) ||
		errors.Is(err, circuitbreaker.ErrTooManyRequests) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return false
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		// Check for PostgreSQL error codes that indicate transient issues.
		// See: https://www.postgresql.org/docs/current/errcodes-appendix.html
		switch pgErr.Code {
		// Class 40: Transaction Rollback (e.g., deadlock, serialization failure)
		case "40001", "40P01":
			return true
		// Class 53: Insufficient Resources (e.g., too many connections)
		case "53300":
			return true
		// Class 08: Connection Exception
		case "08000", "08001", "08003", "08004", "08006", "08007", "08P01":
			return true
		}
	}

	// Check for generic network errors that are temporary
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return false
}

func (rd *ResilientDatabase) QueryWithRetry(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	// Determine if this should go to write or read pools
	var pool *pgxpool.Pool

	if useMaster, ok := ctx.Value(consts.UseMasterDBKey).(bool); ok && useMaster {
		// Explicitly requested to use master/write database
		db := rd.getOperationalDatabaseForOperation(true)
		pool = db.WritePool
	} else {
		// Use read database for queries by default
		db := rd.getOperationalDatabaseForOperation(false)
		pool = db.ReadPool
	}

	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}

	var rows pgx.Rows
	err := retry.WithRetryAdvanced(ctx, func() error {
		queryCtx, cancel := rd.withTimeout(ctx, timeoutRead)
		defer cancel()

		result, cbErr := rd.queryBreaker.Execute(func() (interface{}, error) {
			r, queryErr := pool.Query(queryCtx, sql, args...)
			return r, queryErr
		})

		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				// For non-retryable errors, we'll break the retry loop by returning nil from WithRetry
				// and handle the error outside
				return cbErr
			}
			logger.Debug("Retrying query due to retryable error", "error", cbErr)
			return cbErr // It's retryable, so return the error to signal a retry.
		}

		rows = result.(pgx.Rows)
		return nil
	}, config)

	return rows, err
}

// resilientRow implements the pgx.Row interface to defer the Scan operation
// and execute it within the retry and circuit breaker logic.
type resilientRow struct {
	ctx    context.Context
	rd     *ResilientDatabase
	sql    string
	args   []interface{}
	config retry.BackoffConfig
}

// Scan executes the query and scans the result. This is where the retry and
// circuit breaker logic is actually applied for the query.
func (r *resilientRow) Scan(dest ...interface{}) error {
	op := func(ctx context.Context) (interface{}, error) {
		var pool *pgxpool.Pool
		if useMaster, ok := r.ctx.Value(consts.UseMasterDBKey).(bool); ok && useMaster {
			db := r.rd.getOperationalDatabaseForOperation(true)
			pool = db.WritePool
		} else {
			db := r.rd.getOperationalDatabaseForOperation(false)
			pool = db.ReadPool
		}
		// The error from Scan (including pgx.ErrNoRows) is returned directly.
		// The helper will correctly handle pgx.ErrNoRows as a non-retryable error.
		return nil, pool.QueryRow(ctx, r.sql, r.args...).Scan(dest...)
	}

	// Use the helper to execute the operation with retries and circuit breaker.
	// Pass pgx.ErrNoRows as a non-retryable error.
	_, err := r.rd.executeReadWithRetry(r.ctx, r.config, timeoutRead, op, pgx.ErrNoRows)
	return err
}

func (rd *ResilientDatabase) QueryRowWithRetry(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     3 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
	}
	return &resilientRow{ctx: ctx, rd: rd, sql: sql, args: args, config: config}
}

func (rd *ResilientDatabase) ExecWithRetry(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	// This operation is now transactional, which is an improvement.
	config := retry.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     10 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      2, // Writes are less safe to retry.
	}

	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return tx.Exec(ctx, sql, args...)
	}

	result, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutWrite, op)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	return result.(pgconn.CommandTag), nil
}

func (rd *ResilientDatabase) BeginTxWithRetry(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
	config := retry.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      2,
	}

	var tx pgx.Tx
	err := retry.WithRetryAdvanced(ctx, func() error {
		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		result, cbErr := rd.writeBreaker.Execute(func() (interface{}, error) {
			t, txErr := rd.getOperationalDatabaseForOperation(true).BeginTx(writeCtx, txOptions)
			return t, txErr
		})

		if cbErr != nil {
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			logger.Debug("Retrying BeginTx due to retryable error", "error", cbErr)
			return cbErr
		}

		tx = result.(pgx.Tx)
		return nil
	}, config)

	return tx, err
}

// UpdatePasswordWithRetry updates a user's password with resilience.
func (rd *ResilientDatabase) UpdatePasswordWithRetry(ctx context.Context, address, newHashedPassword string) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).UpdatePassword(ctx, tx, address, newHashedPassword)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutWrite, op)
	return err
}

// GetLastServerAddressWithRetry retrieves the last server address a user connected to, with retry logic.
func (rd *ResilientDatabase) GetLastServerAddressWithRetry(ctx context.Context, accountID int64) (string, time.Time, error) {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      3,
	}

	op := func(ctx context.Context) (interface{}, error) {
		addr, t, err := rd.getOperationalDatabaseForOperation(false).GetLastServerAddress(ctx, accountID)
		if err != nil {
			return nil, err
		}
		return []interface{}{addr, t}, nil
	}

	result, err := rd.executeReadWithRetry(ctx, config, timeoutRead, op, consts.ErrNoServerAffinity)
	if err != nil {
		return "", time.Time{}, err
	}

	resSlice := result.([]interface{})
	return resSlice[0].(string), resSlice[1].(time.Time), nil
}

// UpdateLastServerAddressWithRetry updates the last server address a user connected to, with retry logic.
func (rd *ResilientDatabase) UpdateLastServerAddressWithRetry(ctx context.Context, accountID int64, serverAddr string) error {
	config := writeRetryConfig
	config.MaxRetries = 3 // Can be slightly more aggressive for this simple update.

	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).UpdateLastServerAddress(ctx, tx, accountID, serverAddr)
	}

	_, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutWrite, op)
	return err
}

func (rd *ResilientDatabase) Close() {
	if rd.failoverManager == nil {
		// This case is for when it's initialized without runtime failover.
		// The current code doesn't do this, but it's safe.
		return
	}
	// Stop the health checker
	close(rd.failoverManager.healthCheckStop)

	// Wait for all background goroutines to finish
	logger.Info("Waiting for background goroutines to finish", "component", "RESILIENT-FAILOVER")
	rd.failoverManager.healthCheckWg.Wait()
	logger.Info("All background goroutines finished", "component", "RESILIENT-FAILOVER")

	// Close all managed pools
	for _, pool := range rd.failoverManager.writePools {
		pool.database.Close()
	}

	// Close read pools only if they're different from write pools
	if rd.failoverManager.readPoolsAreDistinct() {
		for _, pool := range rd.failoverManager.readPools {
			pool.database.Close()
		}
	}
}

func (rd *ResilientDatabase) GetQueryBreakerState() circuitbreaker.State {
	return rd.queryBreaker.State()
}

func (rd *ResilientDatabase) GetWriteBreakerState() circuitbreaker.State {
	return rd.writeBreaker.State()
}

// --- Importer/Exporter Wrappers ---

var importExportRetryConfig = retry.BackoffConfig{
	InitialInterval: 500 * time.Millisecond,
	MaxInterval:     10 * time.Second,
	Multiplier:      2.0,
	Jitter:          true,
	MaxRetries:      3,
}

func (rd *ResilientDatabase) DeleteMessageByHashAndMailboxWithRetry(ctx context.Context, userID, mailboxID int64, hash string) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return rd.getOperationalDatabaseForOperation(true).DeleteMessageByHashAndMailbox(ctx, tx, userID, mailboxID, hash)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, importExportRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) CompleteS3UploadWithRetry(ctx context.Context, hash string, accountID int64) error {
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).CompleteS3Upload(ctx, tx, hash, accountID)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, importExportRetryConfig, timeoutWrite, op)
	return err
}

// --- Health Status Wrappers ---

func (rd *ResilientDatabase) StoreHealthStatusWithRetry(ctx context.Context, hostname string, componentName string, status db.ComponentStatus, lastError error, checkCount, failCount int, metadata map[string]interface{}) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
	}
	op := func(ctx context.Context, tx pgx.Tx) (interface{}, error) {
		return nil, rd.getOperationalDatabaseForOperation(true).StoreHealthStatus(ctx, tx, hostname, componentName, status, lastError, checkCount, failCount, metadata)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutWrite, op)
	return err
}

// --- Runtime Failover Implementation ---

// newRuntimeFailoverManager creates a new runtime failover manager with separate read/write pools
func newRuntimeFailoverManager(ctx context.Context, config *config.DatabaseConfig, runMigrations bool) (*RuntimeFailoverManager, error) {
	manager := &RuntimeFailoverManager{
		writePools:      make([]*DatabasePool, 0),
		readPools:       make([]*DatabasePool, 0),
		failedReplicas:  make([]*FailedReplica, 0),
		config:          config,
		healthCheckStop: make(chan struct{}),
	}

	// Create database pools for all write hosts
	if config.Write != nil && len(config.Write.Hosts) > 0 {
		for i, host := range config.Write.Hosts {
			// Only run migrations and acquire lock for the very first write pool.
			isFirstPool := (i == 0)
			pool, err := createDatabasePool(ctx, host, config.Write, config.GetDebug(), "write", runMigrations && isFirstPool, isFirstPool)
			if err != nil {
				logger.Error("Failed to create write pool for host", "component", "RESILIENT-FAILOVER", "host", host, "error", err)
				continue
			}

			dbPool := &DatabasePool{
				database: pool,
				host:     host,
			}
			dbPool.isHealthy.Store(true) // Start as healthy

			manager.writePools = append(manager.writePools, dbPool)

			// First pool becomes the current one
			if i == 0 {
				manager.currentWriteIdx.Store(0)
			}
		}
	}

	// Create database pools for all read hosts
	if config.Read != nil && len(config.Read.Hosts) > 0 {
		logger.Info("Attempting to connect to read replicas", "component", "RESILIENT-FAILOVER", "count", len(config.Read.Hosts))
		successCount := 0
		for _, host := range config.Read.Hosts {
			// Never run migrations or acquire lock for read pools.
			pool, err := createDatabasePool(ctx, host, config.Read, config.GetDebug(), "read", false, false)
			if err != nil {
				logger.Warn("Failed to connect to read replica, will retry periodically", "component", "RESILIENT-FAILOVER", "host", host, "error", err)

				// Track this failed replica for reconnection attempts
				failedReplica := &FailedReplica{
					host:           host,
					endpointConfig: config.Read,
					lastAttempt:    time.Now(),
					attemptCount:   1,
				}
				manager.failedReplicas = append(manager.failedReplicas, failedReplica)
				continue
			}

			dbPool := &DatabasePool{
				database: pool,
				host:     host,
			}
			dbPool.isHealthy.Store(true) // Start as healthy

			manager.readPools = append(manager.readPools, dbPool)
			successCount++

			// First successful pool becomes the current one
			if successCount == 1 {
				manager.currentReadIdx.Store(int64(len(manager.readPools) - 1))
			}
		}
		if successCount > 0 {
			logger.Info("Successfully connected to read replicas", "component", "RESILIENT-FAILOVER", "success_count", successCount, "total", len(config.Read.Hosts))
		}
		if len(manager.failedReplicas) > 0 {
			logger.Info("Read replicas failed at startup, will attempt reconnection", "component", "RESILIENT-FAILOVER", "failed_count", len(manager.failedReplicas))
		}
	}

	// Fallback: if no read pools, use write pools for reads
	if len(manager.readPools) == 0 && len(manager.writePools) > 0 {
		if config.Read != nil && len(config.Read.Hosts) > 0 {
			logger.Warn("All read replicas unreachable at startup, falling back to write pools, will automatically reconnect when they recover", "component", "RESILIENT-FAILOVER")
		} else {
			logger.Info("No read pools configured, using write pools for read operations", "component", "RESILIENT-FAILOVER")
		}
		manager.readPools = manager.writePools
		manager.currentReadIdx.Store(manager.currentWriteIdx.Load())
	}

	if len(manager.writePools) == 0 {
		return nil, fmt.Errorf("no healthy database pools available")
	}

	logger.Info("Created runtime failover manager", "component", "RESILIENT-FAILOVER", "write_pools", len(manager.writePools), "read_pools", len(manager.readPools))
	return manager, nil
}

// createDatabasePool creates a single database connection pool
func createDatabasePool(ctx context.Context, host string, endpointConfig *config.DatabaseEndpointConfig, logQueries bool, poolType string, runMigrations bool, acquireLock bool) (*db.Database, error) {
	// Create a temporary config for this single host
	// Note: We use Write endpoint config even for read pools because db.NewDatabaseFromConfig
	// expects Write to be populated. The actual pool type is tracked by the poolType parameter.
	tempConfig := &config.DatabaseConfig{
		LogQueries: logQueries,
		Write: &config.DatabaseEndpointConfig{
			Hosts:           []string{host},
			Port:            endpointConfig.Port,
			User:            endpointConfig.User,
			Password:        endpointConfig.Password,
			Name:            endpointConfig.Name,
			TLSMode:         endpointConfig.TLSMode,
			MaxConns:        endpointConfig.MaxConns,
			MinConns:        endpointConfig.MinConns,
			MaxConnLifetime: endpointConfig.MaxConnLifetime,
			MaxConnIdleTime: endpointConfig.MaxConnIdleTime,
		},
		PoolTypeOverride: poolType, // Pass the actual pool type for logging
	}

	database, err := db.NewDatabaseFromConfig(ctx, tempConfig, runMigrations, acquireLock)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s database pool for %s: %w", poolType, host, err)
	}

	return database, nil
}

// getCurrentDatabase returns the current active database pool
func (rd *ResilientDatabase) getCurrentDatabase() *db.Database {
	return rd.getCurrentDatabaseForOperation(true)
}

// getCurrentDatabaseForOperation returns the current active database pool for the specified operation type
func (rd *ResilientDatabase) getCurrentDatabaseForOperation(isWrite bool) *db.Database {
	if rd.failoverManager == nil {
		panic("failover manager not initialized")
	}

	rd.failoverManager.mu.RLock()
	defer rd.failoverManager.mu.RUnlock()

	if isWrite {
		if len(rd.failoverManager.writePools) == 0 {
			panic("no write database pools available")
		}

		currentIdx := rd.failoverManager.currentWriteIdx.Load()
		if currentIdx >= 0 && int(currentIdx) < len(rd.failoverManager.writePools) {
			return rd.failoverManager.writePools[currentIdx].database
		}

		// Fallback to first write pool
		return rd.failoverManager.writePools[0].database
	} else {
		if len(rd.failoverManager.readPools) == 0 {
			panic("no read database pools available")
		}

		currentIdx := rd.failoverManager.currentReadIdx.Load()
		if currentIdx >= 0 && int(currentIdx) < len(rd.failoverManager.readPools) {
			return rd.failoverManager.readPools[currentIdx].database
		}

		// Fallback to first read pool
		return rd.failoverManager.readPools[0].database
	}
}

// getOperationalDatabaseForOperation returns the database to use for operations, with runtime failover
func (rd *ResilientDatabase) getOperationalDatabaseForOperation(isWrite bool) *db.Database {
	if rd.failoverManager == nil {
		panic("failover manager not initialized")
	}

	// Try to get a healthy database, with failover if needed
	return rd.getHealthyDatabaseWithFailover(isWrite)
}

// getHealthyDatabaseWithFailover attempts to get a healthy database, failing over if necessary
func (rd *ResilientDatabase) getHealthyDatabaseWithFailover(isWrite bool) *db.Database {
	var pools []*DatabasePool
	var currentIdx int64

	rd.failoverManager.mu.RLock()
	if isWrite {
		pools = rd.failoverManager.writePools
		currentIdx = rd.failoverManager.currentWriteIdx.Load()
	} else {
		pools = rd.failoverManager.readPools
		currentIdx = rd.failoverManager.currentReadIdx.Load()
	}
	rd.failoverManager.mu.RUnlock()

	if len(pools) == 0 {
		panic("no database pools available")
	}

	// --- Fast Path (Read Lock) ---
	// Check if the current pool is healthy. This is the most common case.
	rd.failoverManager.mu.RLock()
	currentPool := pools[currentIdx]
	isHealthy := currentPool.isHealthy.Load()
	rd.failoverManager.mu.RUnlock()

	if isHealthy {
		return currentPool.database
	}

	// --- Slow Path (Write Lock) ---
	// The current pool is unhealthy. Acquire a write lock to perform a failover.
	rd.failoverManager.mu.Lock()
	defer rd.failoverManager.mu.Unlock()

	// Double-check: Another goroutine might have already performed the failover while we were waiting for the lock.
	if isWrite {
		currentIdx = rd.failoverManager.currentWriteIdx.Load()
	} else {
		currentIdx = rd.failoverManager.currentReadIdx.Load()
	}

	if int(currentIdx) < len(pools) && pools[currentIdx].isHealthy.Load() {
		return pools[currentIdx].database
	}

	// Iterate through all pools to find a healthy one, starting from the next one.
	numPools := len(pools)
	for i := 1; i <= numPools; i++ {
		nextIdx := (int(currentIdx) + i) % numPools
		if pools[nextIdx].isHealthy.Load() {
			// Found a healthy pool, switch to it.
			if isWrite {
				rd.failoverManager.currentWriteIdx.Store(int64(nextIdx))
				logger.Info("Switched write operations from unhealthy pool to healthy pool", "component", "RESILIENT-FAILOVER", "from", pools[currentIdx].host, "to", pools[nextIdx].host)
			} else {
				rd.failoverManager.currentReadIdx.Store(int64(nextIdx))
				logger.Info("Switched read operations from unhealthy pool to healthy pool", "component", "RESILIENT-FAILOVER", "from", pools[currentIdx].host, "to", pools[nextIdx].host)
			}
			return pools[nextIdx].database
		}
	}

	// If we get here, no healthy pools were found. Return the current (unhealthy) pool as a last resort.
	opType := "read"
	if isWrite {
		opType = "write"
	}
	logger.Warn("No healthy database pools available, continuing with unhealthy pool as last resort", "component", "RESILIENT-FAILOVER", "type", opType, "pool", pools[currentIdx].host)
	return pools[currentIdx].database
}

// startRuntimeHealthChecking starts background health checking for all pools
func (rd *ResilientDatabase) startRuntimeHealthChecking(ctx context.Context) {
	if rd.failoverManager == nil {
		return
	}

	rd.failoverManager.healthCheckWg.Add(1)
	defer rd.failoverManager.healthCheckWg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	logger.Info("Started background health checking", "component", "RESILIENT-FAILOVER")

	for {
		select {
		case <-ctx.Done():
			logger.Info("Stopped background health checking (context done)", "component", "RESILIENT-FAILOVER")
			return
		case <-rd.failoverManager.healthCheckStop:
			logger.Info("Stopped background health checking (close signal)", "component", "RESILIENT-FAILOVER")
			return
		case <-ticker.C:
			rd.performHealthChecks(ctx)
		}
	}
}

// performHealthChecks checks the health of all database pools
func (rd *ResilientDatabase) performHealthChecks(ctx context.Context) {
	if rd.failoverManager == nil {
		return
	}

	// Check write pools
	for _, pool := range rd.failoverManager.writePools {
		go func(p *DatabasePool) {
			rd.checkPoolHealth(ctx, p, "write")
		}(pool)
	}

	// Check read pools (only if they're different from write pools)
	if rd.failoverManager.readPoolsAreDistinct() {
		for _, pool := range rd.failoverManager.readPools {
			go func(p *DatabasePool) {
				rd.checkPoolHealth(ctx, p, "read")
			}(pool)
		}
	}

	// Attempt to reconnect to failed read replicas
	rd.attemptReconnectFailedReplicas(ctx)
}

// checkPoolHealth checks the health of a single pool
func (rd *ResilientDatabase) checkPoolHealth(ctx context.Context, pool *DatabasePool, poolType string) {
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Use the appropriate pool for health checking
	// For read pools that are distinct from write pools, check the read pool specifically
	// Otherwise, check the write pool (which handles both read and write operations)
	var err error
	if poolType == "read" && rd.failoverManager.readPoolsAreDistinct() {
		err = pool.database.ReadPool.Ping(healthCtx)
	} else {
		err = pool.database.WritePool.Ping(healthCtx)
	}

	wasHealthy := pool.isHealthy.Load()
	isHealthyNow := (err == nil)

	if wasHealthy != isHealthyNow {
		pool.isHealthy.Store(isHealthyNow)
		if isHealthyNow {
			logger.Info("Database pool recovered", "component", "RESILIENT-FAILOVER", "type", poolType, "host", pool.host)
		} else {
			logger.Warn("Database pool failed health check", "component", "RESILIENT-FAILOVER", "type", poolType, "host", pool.host, "error", err)
			pool.lastFailure.Store(time.Now().Unix())
			pool.failCount.Add(1)
		}
	}
}

// attemptReconnectFailedReplicas tries to reconnect to read replicas that failed at startup
func (rd *ResilientDatabase) attemptReconnectFailedReplicas(ctx context.Context) {
	rd.failoverManager.mu.Lock()
	defer rd.failoverManager.mu.Unlock()

	if len(rd.failoverManager.failedReplicas) == 0 {
		return
	}

	// Process failed replicas (iterate backwards so we can remove items)
	for i := len(rd.failoverManager.failedReplicas) - 1; i >= 0; i-- {
		replica := rd.failoverManager.failedReplicas[i]

		replica.mu.Lock()
		timeSinceLastAttempt := time.Since(replica.lastAttempt)
		attemptCount := replica.attemptCount
		replica.mu.Unlock()

		// Use exponential backoff: 30s, 1m, 2m, 5m, 10m, then every 10m
		var backoffDuration time.Duration
		switch {
		case attemptCount <= 1:
			backoffDuration = 30 * time.Second
		case attemptCount == 2:
			backoffDuration = 1 * time.Minute
		case attemptCount == 3:
			backoffDuration = 2 * time.Minute
		case attemptCount == 4:
			backoffDuration = 5 * time.Minute
		default:
			backoffDuration = 10 * time.Minute
		}

		if timeSinceLastAttempt < backoffDuration {
			continue // Not time to retry yet
		}

		// Attempt reconnection
		logger.Info("Attempting to reconnect to read replica", "component", "RESILIENT-FAILOVER", "host", replica.host, "attempt", attemptCount+1)

		pool, err := createDatabasePool(ctx, replica.host, replica.endpointConfig, rd.config.GetDebug(), "read", false, false)

		replica.mu.Lock()
		replica.lastAttempt = time.Now()
		replica.attemptCount++
		replica.mu.Unlock()

		if err != nil {
			logger.Debug("Failed to reconnect to read replica", "component", "RESILIENT-FAILOVER", "host", replica.host, "error", err)
			continue
		}

		// Success! Add the pool and remove from failed list
		logger.Info("Successfully reconnected to read replica", "component", "RESILIENT-FAILOVER", "host", replica.host)

		dbPool := &DatabasePool{
			database: pool,
			host:     replica.host,
		}
		dbPool.isHealthy.Store(true)

		// If we were using write pools as fallback, switch to the new read pool
		wasUsingWritePoolsForReads := !rd.failoverManager.readPoolsAreDistinct()

		rd.failoverManager.readPools = append(rd.failoverManager.readPools, dbPool)

		// If this is the first read pool (was using write pools before), set it as current
		if wasUsingWritePoolsForReads {
			rd.failoverManager.currentReadIdx.Store(int64(len(rd.failoverManager.readPools) - 1))
			logger.Info("Switching from write pools to dedicated read replica for read operations", "component", "RESILIENT-FAILOVER")
		}

		// Remove from failed replicas list
		rd.failoverManager.failedReplicas = append(
			rd.failoverManager.failedReplicas[:i],
			rd.failoverManager.failedReplicas[i+1:]...,
		)
	}
}

// StartPoolMetrics starts a goroutine that periodically collects connection pool metrics
// from all managed database pools (both read and write) and exposes them via Prometheus
func (rd *ResilientDatabase) StartPoolMetrics(ctx context.Context) {
	rd.failoverManager.healthCheckWg.Add(1)
	go func() {
		defer rd.failoverManager.healthCheckWg.Done()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				logger.Info("Stopped pool metrics collection", "component", "RESILIENT-FAILOVER")
				return
			case <-rd.failoverManager.healthCheckStop:
				logger.Info("Stopped pool metrics collection (close signal)", "component", "RESILIENT-FAILOVER")
				return
			case <-ticker.C:
				rd.collectAggregatedPoolStats()
			}
		}
	}()
}

// collectAggregatedPoolStats gathers stats from all write and read pools and updates metrics
func (rd *ResilientDatabase) collectAggregatedPoolStats() {
	rd.failoverManager.mu.RLock()
	defer rd.failoverManager.mu.RUnlock()

	// Import metrics package for accessing the metrics
	// Note: This assumes the metrics package is imported at the top of the file

	// Collect stats from all write pools
	var totalWriteConns, idleWriteConns, inUseWriteConns int32
	for _, pool := range rd.failoverManager.writePools {
		if pool.database != nil && pool.database.WritePool != nil {
			stats := pool.database.WritePool.Stat()
			totalWriteConns += stats.TotalConns()
			idleWriteConns += stats.IdleConns()
			inUseWriteConns += stats.AcquiredConns()
		}
	}

	// Update aggregated write pool metrics
	if len(rd.failoverManager.writePools) > 0 {
		metrics.DBPoolTotalConns.WithLabelValues("write").Set(float64(totalWriteConns))
		metrics.DBPoolIdleConns.WithLabelValues("write").Set(float64(idleWriteConns))
		metrics.DBPoolInUseConns.WithLabelValues("write").Set(float64(inUseWriteConns))
	}

	// Collect stats from read pools only if they are distinct from write pools
	if rd.failoverManager.readPoolsAreDistinct() {
		var totalReadConns, idleReadConns, inUseReadConns int32
		for _, pool := range rd.failoverManager.readPools {
			if pool.database != nil && pool.database.ReadPool != nil {
				stats := pool.database.ReadPool.Stat()
				totalReadConns += stats.TotalConns()
				idleReadConns += stats.IdleConns()
				inUseReadConns += stats.AcquiredConns()
			}
		}

		// Update aggregated read pool metrics
		metrics.DBPoolTotalConns.WithLabelValues("read").Set(float64(totalReadConns))
		metrics.DBPoolIdleConns.WithLabelValues("read").Set(float64(idleReadConns))
		metrics.DBPoolInUseConns.WithLabelValues("read").Set(float64(inUseReadConns))
	} else {
		// If read pools are not distinct, ensure their metrics are zeroed out
		// to avoid reporting stale or incorrect data.
		metrics.DBPoolTotalConns.WithLabelValues("read").Set(0)
		metrics.DBPoolIdleConns.WithLabelValues("read").Set(0)
		metrics.DBPoolInUseConns.WithLabelValues("read").Set(0)
	}
}

// StartPoolHealthMonitoring starts background monitoring of connection pool health
// for all managed database pools with enhanced metrics collection
func (rd *ResilientDatabase) StartPoolHealthMonitoring(ctx context.Context) {
	rd.failoverManager.healthCheckWg.Add(1)
	go func() {
		defer rd.failoverManager.healthCheckWg.Done()
		ticker := time.NewTicker(30 * time.Second) // Align with existing health check interval
		defer ticker.Stop()

		logger.Info("Starting aggregated pool health monitoring every 30s", "component", "RESILIENT-FAILOVER")

		for {
			select {
			case <-ctx.Done():
				logger.Info("Stopping aggregated pool health monitoring", "component", "RESILIENT-FAILOVER")
				return
			case <-rd.failoverManager.healthCheckStop:
				logger.Info("Stopping aggregated pool health monitoring (close signal)", "component", "RESILIENT-FAILOVER")
				return
			case <-ticker.C:
				rd.monitorAggregatedPoolHealth()
			}
		}
	}()
}

// monitorAggregatedPoolHealth performs periodic health checks and updates metrics for all pools
func (rd *ResilientDatabase) monitorAggregatedPoolHealth() {
	rd.failoverManager.mu.RLock()
	defer rd.failoverManager.mu.RUnlock()

	// Monitor write pools
	rd.monitorPoolGroup(rd.failoverManager.writePools, "write")

	// Monitor read pools only if they are distinct
	if rd.failoverManager.readPoolsAreDistinct() {
		rd.monitorPoolGroup(rd.failoverManager.readPools, "read")
	}
}

// monitorPoolGroup monitors a group of database pools (write or read)
func (rd *ResilientDatabase) monitorPoolGroup(pools []*DatabasePool, poolType string) {
	var (
		totalConns      int32
		idleConns       int32
		acquiredConns   int32
		maxConns        int32
		exhaustionCount int
	)

	for _, pool := range pools {
		if pool.database == nil {
			continue
		}

		var poolToCheck *pgxpool.Pool
		if poolType == "write" && pool.database.WritePool != nil {
			poolToCheck = pool.database.WritePool
		} else if poolType == "read" && pool.database.ReadPool != nil {
			poolToCheck = pool.database.ReadPool
		}

		if poolToCheck != nil {
			stats := poolToCheck.Stat()
			totalConns += stats.TotalConns()
			idleConns += stats.IdleConns()
			acquiredConns += stats.AcquiredConns()
			maxConns += stats.MaxConns()

			// Check for pool exhaustion (>95% utilization)
			if stats.MaxConns() > 0 {
				utilization := float64(stats.AcquiredConns()) / float64(stats.MaxConns())
				if utilization > 0.95 {
					exhaustionCount++
					logger.Warn("Database pool near exhaustion", "component", "RESILIENT-FAILOVER", "type",
						poolType, pool.host, utilization*100)
				}
			}

			// Check for slow connection acquisition
			// Note: pgxpool.Stat() doesn't provide acquisition duration directly
			// This would need to be tracked separately or estimated
		}
	}

	// Update aggregated metrics
	metrics.DBPoolTotalConns.WithLabelValues(poolType).Set(float64(totalConns))
	metrics.DBPoolIdleConns.WithLabelValues(poolType).Set(float64(idleConns))
	metrics.DBPoolInUseConns.WithLabelValues(poolType).Set(float64(acquiredConns))

	if exhaustionCount > 0 {
		metrics.DBPoolExhaustion.WithLabelValues(poolType).Add(float64(exhaustionCount))
	}

	logger.Info("Pools health status", "component", "RESILIENT-FAILOVER", "type", poolType, "total_conns", totalConns, "idle", idleConns, "in_use", acquiredConns, "pools", len(pools))
}
