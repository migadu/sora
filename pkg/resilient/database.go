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
//	mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, AccountID, "INBOX")
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
// Only the database failing counts against them (see isDatabaseFailure): an error the
// database answered with, such as a rejected request, is a success.
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
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
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

// FailedHost tracks a database host (read replica or write host) that failed to
// connect at startup; it is retried until it connects.
type FailedHost struct {
	host           string
	poolType       string // "write" or "read"
	endpointConfig *config.DatabaseEndpointConfig
	lastAttempt    time.Time
	attemptCount   int
	mu             sync.Mutex
}

// RuntimeFailoverManager manages multiple database pools and handles failover
type RuntimeFailoverManager struct {
	writePools      []*DatabasePool
	readPools       []*DatabasePool
	failedHosts     []*FailedHost // Hosts that failed to connect at startup
	currentWriteIdx atomic.Int64
	currentReadIdx  atomic.Int64
	// readsUseWritePools describes which hosts the readPools slice contains.
	// readsOnWritePools records a runtime fallback from unhealthy replicas.
	readsUseWritePools atomic.Bool
	readsOnWritePools  atomic.Bool
	config             *config.DatabaseConfig
	healthCheckStop    chan struct{}
	healthCheckWg      sync.WaitGroup
	mu                 sync.RWMutex
}

// readPoolsAreDistinct reports whether the read pools are replicas rather than the
// write pools serving reads.
func (fm *RuntimeFailoverManager) readPoolsAreDistinct() bool {
	return !fm.readsUseWritePools.Load()
}

type ResilientDatabase struct {
	// Runtime failover support
	failoverManager *RuntimeFailoverManager

	// cleanupLock holds the cluster-wide cleanup advisory lock for the duration of a
	// cleanup cycle (AcquireCleanupLockWithRetry / ReleaseCleanupLockWithRetry).
	cleanupLockMu sync.Mutex
	cleanupLock   *db.AdvisoryLockTx

	// Circuit breakers (per-operation type)
	queryBreaker *circuitbreaker.CircuitBreaker
	writeBreaker *circuitbreaker.CircuitBreaker

	// Database configuration for timeouts
	config *config.DatabaseConfig

	// Precomputed "SET LOCAL lock_timeout = <ms>" statement issued at the start of
	// every write transaction (empty when lock_timeout is disabled). Transaction-
	// scoped so it is correct under every PgBouncer pooling mode. See
	// executeWriteInTxWithRetry and DatabaseConfig.GetLockTimeout.
	lockTimeoutStmt string

	// Persistent authentication cache (optional, nil if disabled)
	authCache authCacheInterface

	// Close synchronization to prevent race with health checker
	closeOnce sync.Once
}

// authCacheInterface defines the interface for the persistent auth cache.
// This avoids a direct import cycle with the authcache package.
type authCacheInterface interface {
	Get(ctx context.Context, address string) (accountID int64, hashedPassword string, err error)
	Put(ctx context.Context, address string, accountID int64, hashedPassword string) error
	Invalidate(ctx context.Context, address string) error
	InvalidateAccount(ctx context.Context, accountID int64) error
}

// SetAuthCache sets the persistent authentication cache on the resilient database.
// This should be called after creating the ResilientDatabase if auth cache is enabled.
func (rd *ResilientDatabase) SetAuthCache(cache authCacheInterface) {
	rd.authCache = cache
}

// isDatabaseFailure reports whether err shows the database failing: unreachable or
// dropping the connection, timing out, out of resources, shutting down, or reporting an
// internal error. Only these count against the circuit breakers. Anything else is an
// answer from a working database or a decision made without it — a not-found, a
// constraint violation, a rejected request, an *imap.Error from a stream callback — and
// counting it would let a few bad requests (say, deleting a primary credential three
// times) open the write breaker and refuse every write on the node, deliveries
// included. The rule goes by the kind of error rather than an allowlist of application
// errors, so a new rejection cannot trip a breaker by being left off a list.
func isDatabaseFailure(err error) bool {
	if err == nil {
		return false
	}
	// The breaker refusing a request: the database is considered unavailable.
	if errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) || errors.Is(err, circuitbreaker.ErrTooManyRequests) {
		return true
	}
	// The caller giving up (client gone, shutdown) says nothing about the database.
	if errors.Is(err, context.Canceled) {
		return false
	}
	var connectErr *pgconn.ConnectError
	if errors.As(err, &connectErr) {
		return true
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return isDatabaseFailureSQLState(pgErr.Code)
	}
	// The connection broke or timed out (pgx wraps the net/io error it read).
	var netErr net.Error
	return errors.As(err, &netErr) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, pgconn.ErrConnClosed) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF)
}

// isDatabaseFailureSQLState reports whether a PostgreSQL error code is the server failing
// rather than refusing the statement (PostgreSQL documentation, Appendix A "PostgreSQL
// Error Codes"). Data exceptions (22), integrity constraint violations (23), syntax or
// access rule violations (42), transaction rollbacks such as deadlocks (40) and the rest
// are answers to the statement.
func isDatabaseFailureSQLState(code string) bool {
	switch code {
	case "25006", // read_only_sql_transaction: the write pool reached a standby after a failover
		"55P03": // lock_not_available: lock_timeout elapsed waiting for a row lock
		return true
	}
	if len(code) != 5 {
		return false
	}
	switch code[:2] {
	case "08", // Connection Exception (PgBouncer reports its own failures as 08P01)
		"53", // Insufficient Resources: disk full, out of memory, too many connections
		"57", // Operator Intervention: shutdown, cannot connect now, statement_timeout
		"58", // System Error (errors external to PostgreSQL itself)
		"XX": // Internal Error
		return true
	}
	return false
}

// isBreakerSuccess is the IsSuccessful predicate of both database circuit breakers.
func isBreakerSuccess(err error) bool {
	return !isDatabaseFailure(err)
}

func NewResilientDatabase(ctx context.Context, config *config.DatabaseConfig, enableHealthCheck bool, runMigrations bool) (*ResilientDatabase, error) {
	return NewResilientDatabaseWithOptions(ctx, config, enableHealthCheck, runMigrations, false)
}

// NewResilientDatabaseWithOptions creates a new resilient database with additional options.
// Parameters:
//   - ctx: Context for initialization
//   - config: Database configuration
//   - enableHealthCheck: Enable background health checking
//   - runMigrations: Run database migrations on startup
//   - skipReadReplicas: Skip read replica initialization (use write pool for reads, useful for CLI tools)
func NewResilientDatabaseWithOptions(ctx context.Context, config *config.DatabaseConfig, enableHealthCheck bool, runMigrations bool, skipReadReplicas bool) (*ResilientDatabase, error) {
	// Create circuit breakers
	querySettings := circuitbreaker.DefaultSettings("database_query")
	querySettings.MaxRequests = databaseBreakerMaxRequests
	querySettings.Interval = 15 * time.Second
	querySettings.Timeout = 45 * time.Second
	querySettings.ReadyToTrip = queryBreakerReadyToTrip
	querySettings.OnStateChange = func(name string, from circuitbreaker.State, to circuitbreaker.State) {
		logger.Info("Database query circuit breaker state changed", "component", "RESILIENT-FAILOVER", "name", name, "from", from, "to", to)
	}
	querySettings.IsSuccessful = isBreakerSuccess

	writeSettings := circuitbreaker.DefaultSettings("database_write")
	writeSettings.MaxRequests = databaseBreakerMaxRequests
	writeSettings.Interval = 10 * time.Second
	writeSettings.Timeout = 30 * time.Second
	writeSettings.ReadyToTrip = writeBreakerReadyToTrip
	writeSettings.OnStateChange = func(name string, from circuitbreaker.State, to circuitbreaker.State) {
		logger.Info("Database write circuit breaker state changed", "component", "RESILIENT-FAILOVER", "name", name, "from", from, "to", to)
	}
	writeSettings.IsSuccessful = isBreakerSuccess

	// Create failover manager
	failoverManager, err := newRuntimeFailoverManager(ctx, config, runMigrations, skipReadReplicas)
	if err != nil {
		return nil, fmt.Errorf("failed to create failover manager: %w", err)
	}

	// Precompute the per-write-transaction lock_timeout statement once. A bad
	// duration string falls back to the documented default rather than failing
	// startup, matching the lenient handling of the other timeouts in withTimeout.
	lockTimeout, ltErr := config.GetLockTimeout()
	if ltErr != nil {
		logger.Warn("Invalid lock_timeout, using default 10s", "error", ltErr)
		lockTimeout = 10 * time.Second
	}
	lockTimeoutStmt := ""
	if lockTimeout > 0 {
		// SET does not accept bind parameters; the value is a trusted integer.
		lockTimeoutStmt = fmt.Sprintf("SET LOCAL lock_timeout = %d", lockTimeout.Milliseconds())
	}

	rdb := &ResilientDatabase{
		failoverManager: failoverManager,
		queryBreaker:    circuitbreaker.NewCircuitBreaker(querySettings),
		writeBreaker:    circuitbreaker.NewCircuitBreaker(writeSettings),
		config:          config,
		lockTimeoutStmt: lockTimeoutStmt,
	}

	// Start background health checking if enabled
	if enableHealthCheck {
		rdb.failoverManager.healthCheckWg.Add(1)
		go rdb.startRuntimeHealthChecking(ctx)
	}

	return rdb, nil
}

// databaseBreakerMaxRequests is how many test requests the database circuit breakers let
// through while half-open: more than the default, for faster recovery.
const databaseBreakerMaxRequests = 10

// queryBreakerReadyToTrip decides when the database query circuit breaker opens.
func queryBreakerReadyToTrip(counts circuitbreaker.Counts) bool {
	results := counts.Results()
	failureRatio := float64(counts.TotalFailures) / float64(results)

	// In half-open state, if we've used all allowed requests and majority failed, trip immediately
	// This prevents deadlock where circuit stays half-open forever
	if results >= databaseBreakerMaxRequests && failureRatio >= 0.6 {
		logger.Warn("Query circuit breaker ready to trip (half-open exhausted)", "component", "RESILIENT-FAILOVER",
			"requests", counts.Requests, "results", results, "failures", counts.TotalFailures,
			"failure_ratio", fmt.Sprintf("%.2f%%", failureRatio*100),
			"max_requests", databaseBreakerMaxRequests)
		return true
	}

	// In normal operation, require at least 8 results to establish a pattern
	shouldTrip := results >= 8 && failureRatio >= 0.6
	if shouldTrip {
		logger.Warn("Query circuit breaker ready to trip", "component", "RESILIENT-FAILOVER",
			"requests", counts.Requests, "results", results, "failures", counts.TotalFailures,
			"failure_ratio", fmt.Sprintf("%.2f%%", failureRatio*100),
			"consecutive_failures", counts.ConsecutiveFailures)
	}
	return shouldTrip
}

// writeBreakerReadyToTrip decides when the database write circuit breaker opens.
func writeBreakerReadyToTrip(counts circuitbreaker.Counts) bool {
	results := counts.Results()
	failureRatio := float64(counts.TotalFailures) / float64(results)

	// In half-open state, if we've used all allowed requests and majority failed, trip immediately
	// This prevents deadlock where circuit stays half-open forever
	if results >= databaseBreakerMaxRequests && failureRatio >= 0.5 {
		logger.Warn("Write circuit breaker ready to trip (half-open exhausted)", "component", "RESILIENT-FAILOVER",
			"requests", counts.Requests, "results", results, "failures", counts.TotalFailures,
			"failure_ratio", fmt.Sprintf("%.2f%%", failureRatio*100),
			"max_requests", databaseBreakerMaxRequests)
		return true
	}

	// In normal operation, require at least 5 results to establish a pattern
	shouldTrip := results >= 5 && failureRatio >= 0.5
	if shouldTrip {
		logger.Warn("Write circuit breaker ready to trip", "component", "RESILIENT-FAILOVER",
			"requests", counts.Requests, "results", results, "failures", counts.TotalFailures,
			"failure_ratio", fmt.Sprintf("%.2f%%", failureRatio*100),
			"consecutive_failures", counts.ConsecutiveFailures)
	}
	return shouldTrip
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

// PingReadPools pings, on every read host, the pool reads are served from: each
// replica's, or the write hosts' while reads use them. The error names every host that
// failed.
func (rd *ResilientDatabase) PingReadPools(ctx context.Context) error {
	rd.failoverManager.mu.RLock()
	pools := append([]*DatabasePool(nil), rd.failoverManager.readPools...)
	rd.failoverManager.mu.RUnlock()

	errs := make([]error, len(pools))
	var wg sync.WaitGroup
	for i, p := range pools {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.database.ReadPool.Ping(ctx); err != nil {
				errs[i] = fmt.Errorf("read pool %s: %w", p.host, err)
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// GetQueryTimeout returns the configured query timeout for read operations
// This is useful when code needs to create its own context with appropriate timeout
func (rd *ResilientDatabase) GetQueryTimeout() time.Duration {
	timeout, err := rd.config.GetQueryTimeout()
	if err != nil {
		logger.Warn("Invalid global query_timeout, using default", "error", err)
		return 30 * time.Second
	}
	return timeout
}

// GetWriteTimeout returns the configured write timeout for write operations
// This is useful when code needs to create its own context with appropriate timeout
func (rd *ResilientDatabase) GetWriteTimeout() time.Duration {
	timeout, err := rd.config.GetWriteTimeout()
	if err != nil {
		logger.Warn("Invalid global write_timeout, using default", "error", err)
		return 15 * time.Second
	}
	return timeout
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

// logsWriteErrorAtWarn reports whether an error from a write through the breaker is
// logged at WARN: a retryable error (a deadlock or serialization failure, which is retried
// and does not count against the breaker, or a connection timeout), or the database
// failing while the breaker is not CLOSED. Anything else, such as a rejected request or a
// not-found, is logged at DEBUG.
func (rd *ResilientDatabase) logsWriteErrorAtWarn(err error, state circuitbreaker.State) bool {
	return rd.isRetryableError(err) || (isDatabaseFailure(err) && state != circuitbreaker.StateClosed)
}

func (rd *ResilientDatabase) QueryWithRetry(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	// Determine if this should go to write or read pools
	var pool *pgxpool.Pool

	if useMaster, ok := ctx.Value(consts.UseMasterDBKey).(bool); ok && useMaster {
		// Explicitly requested to use master/write database
		db := rd.getOperationalDatabaseForOperation(ctx, true)
		pool = db.WritePool
	} else {
		// Use read database for queries by default
		db := rd.getOperationalDatabaseForOperation(ctx, false)
		pool = db.ReadPool
	}

	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     5 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
		OperationName:   "db_query",
	}

	var rows pgx.Rows
	err := retry.WithRetryAdvanced(ctx, func() error {
		queryCtx, cancel := rd.withTimeout(ctx, timeoutRead)

		result, cbErr := rd.queryBreaker.Execute(func() (any, error) {
			r, queryErr := pool.Query(queryCtx, sql, args...)
			return r, queryErr
		})

		if cbErr != nil {
			cancel()
			if !rd.isRetryableError(cbErr) {
				return retry.Stop(cbErr)
			}
			logger.Debug("Retrying query due to retryable error", "error", cbErr)
			return cbErr // It's retryable, so return the error to signal a retry.
		}

		// pgx reads the rows under queryCtx until they are closed, so the context
		// lives as long as the rows do.
		rows = &cancelOnCloseRows{Rows: result.(pgx.Rows), cancel: cancel}
		return nil
	}, config)

	return rows, err
}

// cancelOnCloseRows releases the query's timeout context once the rows are done:
// when the caller closes them, or when Next reports the end (pgx closes rows itself
// then, so a caller that drains them need not call Close).
type cancelOnCloseRows struct {
	pgx.Rows
	cancel context.CancelFunc
}

func (r *cancelOnCloseRows) Next() bool {
	if r.Rows.Next() {
		return true
	}
	r.cancel()
	return false
}

func (r *cancelOnCloseRows) Close() {
	r.Rows.Close()
	r.cancel()
}

// resilientRow implements the pgx.Row interface to defer the Scan operation
// and execute it within the retry and circuit breaker logic.
type resilientRow struct {
	ctx    context.Context
	rd     *ResilientDatabase
	sql    string
	args   []any
	config retry.BackoffConfig
}

// Scan executes the query and scans the result. This is where the retry and
// circuit breaker logic is actually applied for the query.
func (r *resilientRow) Scan(dest ...any) error {
	op := func(ctx context.Context) (any, error) {
		var pool *pgxpool.Pool
		if useMaster, ok := r.ctx.Value(consts.UseMasterDBKey).(bool); ok && useMaster {
			db := r.rd.getOperationalDatabaseForOperation(r.ctx, true)
			pool = db.WritePool
		} else {
			db := r.rd.getOperationalDatabaseForOperation(r.ctx, false)
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

func (rd *ResilientDatabase) QueryRowWithRetry(ctx context.Context, sql string, args ...any) pgx.Row {
	config := retry.BackoffConfig{
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     3 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      3,
		OperationName:   "db_query_row",
	}
	return &resilientRow{ctx: ctx, rd: rd, sql: sql, args: args, config: config}
}

func (rd *ResilientDatabase) ExecWithRetry(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	// This operation is now transactional, which is an improvement.
	config := retry.BackoffConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     10 * time.Second,
		Multiplier:      2.0,
		Jitter:          true,
		MaxRetries:      2, // Writes are less safe to retry.
		OperationName:   "db_exec",
	}

	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
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
		OperationName:   "db_begin_tx",
	}

	var tx pgx.Tx
	err := retry.WithRetryAdvanced(ctx, func() error {
		writeCtx, cancel := rd.withTimeout(ctx, timeoutWrite)
		defer cancel()

		result, cbErr := rd.writeBreaker.Execute(func() (any, error) {
			t, txErr := rd.getOperationalDatabaseForOperation(writeCtx, true).BeginTx(writeCtx, txOptions)
			return t, txErr
		})

		if cbErr != nil {
			// Log circuit breaker state to understand failure patterns
			state := rd.writeBreaker.State()
			counts := rd.writeBreaker.Counts()

			if rd.logsWriteErrorAtWarn(cbErr, state) {
				logger.Warn("Write operation failed through circuit breaker", "component", "RESILIENT-FAILOVER",
					"error", cbErr, "breaker_state", state, "total_failures", counts.TotalFailures,
					"total_requests", counts.Requests, "consecutive_failures", counts.ConsecutiveFailures)
			} else {
				logger.Debug("Write operation returned application error", "component", "RESILIENT-FAILOVER",
					"error", cbErr)
			}

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
// Invalidates the auth cache entry for this user if cache is enabled.
func (rd *ResilientDatabase) UpdatePasswordWithRetry(ctx context.Context, address, newHashedPassword string) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
		OperationName:   "db_update_password",
	}
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).UpdatePassword(ctx, tx, address, newHashedPassword)
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

	// Use sync.Once to ensure Close() is only executed once to prevent race with health checker
	rd.closeOnce.Do(func() {
		// Stop the health checker
		close(rd.failoverManager.healthCheckStop)

		// Wait for all background goroutines to finish
		logger.Info("Waiting for background goroutines to finish", "component", "RESILIENT-FAILOVER")
		rd.failoverManager.healthCheckWg.Wait()
		logger.Info("All background goroutines finished", "component", "RESILIENT-FAILOVER")

		// A cleanup cycle still holding its lock has a pooled connection checked out, and
		// pgxpool.Close waits for every checked-out connection: release it first.
		_ = rd.ReleaseCleanupLockWithRetry(context.Background())

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
	})
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
	OperationName:   "db_import_export",
}

func (rd *ResilientDatabase) DeleteMessageByHashAndMailboxWithRetry(ctx context.Context, AccountID, mailboxID int64, hash string) (int64, error) {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, true).DeleteMessageByHashAndMailbox(ctx, tx, AccountID, mailboxID, hash)
	}
	result, err := rd.executeWriteInTxWithRetry(ctx, importExportRetryConfig, timeoutWrite, op)
	if err != nil {
		return 0, err
	}
	return result.(int64), nil
}

func (rd *ResilientDatabase) CompleteS3UploadWithRetry(ctx context.Context, hash string, accountID int64, writtenKeys []string) error {
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).CompleteS3Upload(ctx, tx, hash, accountID, writtenKeys)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, importExportRetryConfig, timeoutWrite, op)
	return err
}

// --- Health Status Wrappers ---

func (rd *ResilientDatabase) StoreHealthStatusWithRetry(ctx context.Context, hostname string, componentName string, status db.ComponentStatus, lastError error, checkCount, failCount int, metadata map[string]any) error {
	config := retry.BackoffConfig{
		InitialInterval: 250 * time.Millisecond,
		MaxInterval:     2 * time.Second,
		Multiplier:      1.5,
		Jitter:          true,
		MaxRetries:      2,
		OperationName:   "db_store_health_status",
	}
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		return nil, rd.getOperationalDatabaseForOperation(ctx, true).StoreHealthStatus(ctx, tx, hostname, componentName, status, lastError, checkCount, failCount, metadata)
	}
	_, err := rd.executeWriteInTxWithRetry(ctx, config, timeoutWrite, op)
	return err
}

// --- Runtime Failover Implementation ---

// newRuntimeFailoverManager creates a new runtime failover manager with separate read/write pools
func newRuntimeFailoverManager(ctx context.Context, config *config.DatabaseConfig, runMigrations bool, skipReadReplicas bool) (*RuntimeFailoverManager, error) {
	manager := &RuntimeFailoverManager{
		writePools:      make([]*DatabasePool, 0),
		readPools:       make([]*DatabasePool, 0),
		failedHosts:     make([]*FailedHost, 0),
		config:          config,
		healthCheckStop: make(chan struct{}),
	}

	// Create database pools for all write hosts
	// NOTE: We create write pools SEQUENTIALLY (not in parallel like read pools) because:
	// 1. Migrations run once, through the first write host that connects (requires
	//    exclusive migration lock); a host that is down does not skip them
	// 2. Parallel creation could cause connection pool exhaustion during startup
	if config.Write != nil && len(config.Write.Hosts) > 0 {
		migrationsPending := runMigrations
		for i, host := range config.Write.Hosts {
			logger.Info("Creating write pool", "component", "RESILIENT-FAILOVER", "host", host, "index", i, "total", len(config.Write.Hosts))

			pool, err := createDatabasePool(ctx, host, config, config.Write, "write", migrationsPending)
			if err != nil {
				// The schema is shared by every write host: a node must not start on a
				// schema whose migration failed, however many hosts it could reach.
				if errors.Is(err, db.ErrMigrationFailed) {
					return nil, err
				}
				logger.Error("Failed to create write pool for host, will retry periodically", "component", "RESILIENT-FAILOVER", "host", host, "error", err)
				manager.failedHosts = append(manager.failedHosts, &FailedHost{
					host:           host,
					poolType:       "write",
					endpointConfig: config.Write,
					lastAttempt:    time.Now(),
					attemptCount:   1,
				})
				continue
			}
			migrationsPending = false

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

	// Create database pools for all read hosts (in parallel for faster startup)
	// Skip if skipReadReplicas is true (e.g., for CLI tools)
	if !skipReadReplicas && config.Read != nil && len(config.Read.Hosts) > 0 {
		logger.Info("Attempting to connect to read replicas", "component", "RESILIENT-FAILOVER", "count", len(config.Read.Hosts))

		// Use channels to collect results from parallel connection attempts
		type poolResult struct {
			host string
			pool *db.Database
			err  error
		}
		resultChan := make(chan poolResult, len(config.Read.Hosts))

		// Attempt all connections in parallel to minimize startup time
		for _, host := range config.Read.Hosts {
			go func(h string) {
				// Never run migrations for read pools.
				pool, err := createDatabasePool(ctx, h, config, config.Read, "read", false)
				resultChan <- poolResult{host: h, pool: pool, err: err}
			}(host)
		}

		// Collect results
		successCount := 0
		for i := 0; i < len(config.Read.Hosts); i++ {
			result := <-resultChan

			if result.err != nil {
				logger.Warn("Failed to connect to read replica, will retry periodically", "component", "RESILIENT-FAILOVER", "host", result.host, "error", result.err)

				// Track this failed replica for reconnection attempts
				manager.failedHosts = append(manager.failedHosts, &FailedHost{
					host:           result.host,
					poolType:       "read",
					endpointConfig: config.Read,
					lastAttempt:    time.Now(),
					attemptCount:   1,
				})
				continue
			}

			dbPool := &DatabasePool{
				database: result.pool,
				host:     result.host,
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
		if failed := len(config.Read.Hosts) - successCount; failed > 0 {
			logger.Info("Read replicas failed at startup, will attempt reconnection", "component", "RESILIENT-FAILOVER", "failed_count", failed)
		}
	}

	// Fallback: if no read pools, use write pools for reads
	if len(manager.readPools) == 0 && len(manager.writePools) > 0 {
		if !skipReadReplicas && config.Read != nil && len(config.Read.Hosts) > 0 {
			logger.Warn("All read replicas unreachable at startup, falling back to write pools, will automatically reconnect when they recover", "component", "RESILIENT-FAILOVER")
		} else if skipReadReplicas {
			logger.Info("Read replicas disabled for CLI mode, using write pool for all operations", "component", "RESILIENT-FAILOVER")
		} else {
			logger.Info("No read pools configured, using write pools for read operations", "component", "RESILIENT-FAILOVER")
		}
		manager.readPools = manager.writePools
		manager.readsUseWritePools.Store(true)
		manager.currentReadIdx.Store(manager.currentWriteIdx.Load())
	}

	if len(manager.writePools) == 0 {
		return nil, fmt.Errorf("no healthy database pools available")
	}

	logger.Info("Created runtime failover manager", "component", "RESILIENT-FAILOVER", "write_pools", len(manager.writePools), "read_pools", len(manager.readPools))
	return manager, nil
}

// createDatabasePool creates a single database connection pool
func createDatabasePool(ctx context.Context, host string, dbConfig *config.DatabaseConfig, endpointConfig *config.DatabaseEndpointConfig, poolType string, runMigrations bool) (*db.Database, error) {
	// Shallow-copy the endpoint config so overriding Hosts for this single pool
	// preserves every pool setting (including MinIdleConnections, QueryTimeout, etc.)
	// without mutating the caller's config.
	singleHostEndpoint := *endpointConfig
	singleHostEndpoint.Hosts = []string{host}

	// Note: We use Write endpoint config even for read pools because db.NewDatabaseFromConfig
	// expects Write to be populated. The actual pool type is tracked by the poolType parameter.
	//
	// A dedicated read pool keeps heavy writes from starving reads, which only matters on a
	// host that serves both: a write host when [database.read] is not configured. A replica
	// takes no writes, and with [database.read] the write hosts take reads only as a
	// fallback (no healthy replica, or sora-admin, which skips the replicas), where the
	// reads share the write pool. Every other host gets one pool of max_connections.
	readEndpointConfigured := dbConfig.Read != nil && len(dbConfig.Read.Hosts) > 0
	tempConfig := &config.DatabaseConfig{
		Debug:               dbConfig.GetDebug(),
		MigrationTimeout:    dbConfig.MigrationTimeout,
		FetchChunkSize:      dbConfig.FetchChunkSize,
		Write:               &singleHostEndpoint,
		PoolTypeOverride:    poolType, // Pass the actual pool type for logging
		ReadsShareWritePool: poolType != "write" || readEndpointConfigured,
	}

	database, err := db.NewDatabaseFromConfig(ctx, tempConfig, runMigrations)
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
func (rd *ResilientDatabase) getOperationalDatabaseForOperation(ctx context.Context, isWrite bool) *db.Database {
	if rd.failoverManager == nil {
		panic("failover manager not initialized")
	}

	if !isWrite && ctx != nil {
		if useMaster, ok := ctx.Value(consts.UseMasterDBKey).(bool); ok && useMaster {
			isWrite = true
		}
	}

	// Try to get a healthy database, with failover if needed
	return rd.getHealthyDatabaseWithFailover(isWrite)
}

// GetOperationalDatabase returns the underlying database instance for write operations
// This is used by the importer for batch transaction mode
func (rd *ResilientDatabase) GetOperationalDatabase() *db.Database {
	return rd.getOperationalDatabaseForOperation(context.Background(), true)
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
		if !isWrite && rd.failoverManager.readsOnWritePools.CompareAndSwap(true, false) {
			logger.Info("Read operations are back on a read replica", "component", "RESILIENT-FAILOVER", "pool", currentPool.host)
		}
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

	// No read replica is healthy: serve reads from a healthy write pool, as startup does
	// when every replica is down, rather than from a replica known to be failing.
	if !isWrite && rd.failoverManager.readPoolsAreDistinct() {
		writePools := rd.failoverManager.writePools
		writeIdx := int(rd.failoverManager.currentWriteIdx.Load())
		for i := 0; i < len(writePools); i++ {
			p := writePools[(writeIdx+i)%len(writePools)]
			if p.isHealthy.Load() {
				if rd.failoverManager.readsOnWritePools.CompareAndSwap(false, true) {
					logger.Warn("No healthy read replica, serving read operations from the write pool", "component", "RESILIENT-FAILOVER", "pool", p.host)
				}
				return p.database
			}
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
// Note: Caller must have already called healthCheckWg.Add(1) before starting this goroutine
func (rd *ResilientDatabase) startRuntimeHealthChecking(ctx context.Context) {
	if rd.failoverManager == nil {
		return
	}

	defer rd.failoverManager.healthCheckWg.Done()

	// Store local reference to stop channel to avoid race detector warnings
	// The channel itself is never reassigned, only closed
	stopChan := rd.failoverManager.healthCheckStop

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	logger.Info("Started background health checking", "component", "RESILIENT-FAILOVER")

	for {
		select {
		case <-ctx.Done():
			logger.Info("Stopped background health checking (context done)", "component", "RESILIENT-FAILOVER")
			return
		case <-stopChan:
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

	// Attempt to reconnect to hosts that failed at startup
	rd.attemptReconnectFailedHosts(ctx)
}

// isReadOnlyTransactionError returns true when err is a PostgreSQL
// "read_only_sql_transaction" error (SQLSTATE 25006).  This happens when a
// write operation is sent to a server that has become a read-only standby after
// a failover.
func isReadOnlyTransactionError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "25006"
}

// resetCurrentWritePool resets all connections in the current write pool.
// This should be called when we detect the write pool is connected to a read-only
// server (e.g. after a PostgreSQL failover). Resetting forces fresh connections
// that may be routed to the new primary by DNS or a load balancer.
func (rd *ResilientDatabase) resetCurrentWritePool() {
	rd.failoverManager.mu.RLock()
	defer rd.failoverManager.mu.RUnlock()

	currentIdx := rd.failoverManager.currentWriteIdx.Load()
	pools := rd.failoverManager.writePools
	if int(currentIdx) < len(pools) {
		pool := pools[currentIdx]
		if pool.database != nil && pool.database.WritePool != nil {
			logger.Info("Resetting write pool connections after read-only error (failover recovery)",
				"component", "RESILIENT-FAILOVER", "host", pool.host)
			pool.database.WritePool.Reset()
		}
	}
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
		if err == nil {
			// After a PostgreSQL failover the old primary becomes a read-only standby.
			// It still accepts connections and responds to Ping successfully, so a plain
			// Ping cannot detect this situation. We query pg_is_in_recovery() explicitly:
			// it returns true on any standby/replica and false only on the writable primary.
			// When the server is in recovery mode we synthesise an error so the pool is
			// marked unhealthy and its connections are reset, allowing the next connection
			// attempt (after DNS / load-balancer propagation) to reach the new primary.
			var inRecovery bool
			if queryErr := pool.database.WritePool.QueryRow(healthCtx, "SELECT pg_is_in_recovery()").Scan(&inRecovery); queryErr == nil && inRecovery {
				err = fmt.Errorf("write pool host is in read-only recovery mode (failover occurred)")
				logger.Warn("Write pool host is in recovery mode (became a standby replica after failover), resetting connection pool",
					"component", "RESILIENT-FAILOVER", "host", pool.host)
				// Reset pool connections immediately so the next attempt uses a fresh TCP
				// connection that may be routed to the new primary.
				pool.database.WritePool.Reset()
			}
		}
	}

	wasHealthy := pool.isHealthy.Load()
	isHealthyNow := (err == nil)

	if wasHealthy != isHealthyNow {
		pool.isHealthy.Store(isHealthyNow)
		if isHealthyNow {
			logger.Info("Database pool recovered", "component", "RESILIENT-FAILOVER", "type", poolType, "host", pool.host)

			// Reset circuit breakers when database recovers to allow immediate recovery
			// This prevents the circuit breaker from staying OPEN even when the database is healthy
			if poolType == "write" || !rd.failoverManager.readPoolsAreDistinct() {
				// Reset write breaker for write pools or when using write pool for reads
				queryState := rd.queryBreaker.State()
				writeState := rd.writeBreaker.State()

				// Force circuit breakers to half-open state to allow immediate testing
				// This is safe because we've just confirmed the database is responding to pings
				if queryState == circuitbreaker.StateOpen {
					logger.Info("Forcing query circuit breaker to half-open after database recovery", "component", "RESILIENT-FAILOVER")
					rd.queryBreaker.ForceHalfOpen()
				}
				if writeState == circuitbreaker.StateOpen {
					logger.Info("Forcing write circuit breaker to half-open after database recovery", "component", "RESILIENT-FAILOVER")
					rd.writeBreaker.ForceHalfOpen()
				}
			}
		} else {
			logger.Warn("Database pool failed health check", "component", "RESILIENT-FAILOVER", "type", poolType, "host", pool.host, "error", err)
			pool.lastFailure.Store(time.Now().Unix())
			pool.failCount.Add(1)
		}
	}
}

// attemptReconnectFailedHosts tries to reconnect to the read replicas and write hosts
// that failed at startup. It connects without holding the manager's lock: an attempt can
// take the whole connect timeout, and every database operation takes that lock. It runs
// on the health-check goroutine only, so no two attempts race for one host.
func (rd *ResilientDatabase) attemptReconnectFailedHosts(ctx context.Context) {
	fm := rd.failoverManager
	fm.mu.RLock()
	failedHosts := append([]*FailedHost(nil), fm.failedHosts...)
	fm.mu.RUnlock()

	for _, failed := range failedHosts {
		failed.mu.Lock()
		timeSinceLastAttempt := time.Since(failed.lastAttempt)
		attemptCount := failed.attemptCount
		failed.mu.Unlock()

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
		logger.Info("Attempting to reconnect to database host", "component", "RESILIENT-FAILOVER", "type", failed.poolType, "host", failed.host, "attempt", attemptCount+1)

		pool, err := createDatabasePool(ctx, failed.host, rd.config, failed.endpointConfig, failed.poolType, false)

		failed.mu.Lock()
		failed.lastAttempt = time.Now()
		failed.attemptCount++
		failed.mu.Unlock()

		if err != nil {
			logger.Debug("Failed to reconnect to database host", "component", "RESILIENT-FAILOVER", "type", failed.poolType, "host", failed.host, "error", err)
			continue
		}

		// Success! Add the pool and remove from failed list
		logger.Info("Successfully reconnected to database host", "component", "RESILIENT-FAILOVER", "type", failed.poolType, "host", failed.host)

		dbPool := &DatabasePool{
			database: pool,
			host:     failed.host,
		}
		dbPool.isHealthy.Store(true)

		fm.mu.Lock()
		if failed.poolType == "write" {
			// Keep the slices in sync while write hosts also serve reads, without
			// appending into a backing array that readPools may still share.
			writePools := fm.writePools
			fm.writePools = append(writePools[:len(writePools):len(writePools)], dbPool)
			if fm.readsUseWritePools.Load() {
				fm.readPools = fm.writePools
			}
		} else if fm.readsUseWritePools.Load() {
			// The first replica replaces the write hosts as the read pool set.
			fm.readPools = []*DatabasePool{dbPool}
			fm.currentReadIdx.Store(0)
			fm.readsUseWritePools.Store(false)
			logger.Info("Switching from write pools to dedicated read replica for read operations", "component", "RESILIENT-FAILOVER")
		} else {
			readPools := fm.readPools
			fm.readPools = append(readPools[:len(readPools):len(readPools)], dbPool)
		}

		// Remove from failed hosts list
		for i, f := range fm.failedHosts {
			if f == failed {
				fm.failedHosts = append(fm.failedHosts[:i], fm.failedHosts[i+1:]...)
				break
			}
		}
		fm.mu.Unlock()
	}
}

// StartPoolMetrics starts a goroutine that periodically collects connection pool metrics
// from all managed database pools (both read and write) and exposes them via Prometheus
func (rd *ResilientDatabase) StartPoolMetrics(ctx context.Context) {
	rd.failoverManager.healthCheckWg.Add(1)
	// Store local reference to stop channel to avoid race detector warnings
	stopChan := rd.failoverManager.healthCheckStop
	go func() {
		defer rd.failoverManager.healthCheckWg.Done()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				logger.Info("Stopped pool metrics collection", "component", "RESILIENT-FAILOVER")
				return
			case <-stopChan:
				logger.Info("Stopped pool metrics collection (close signal)", "component", "RESILIENT-FAILOVER")
				return
			case <-ticker.C:
				rd.collectAggregatedPoolStats()
			}
		}
	}()
}

// rolePool is one pgx pool the failover manager opened, with the role it serves.
type rolePool struct {
	role string // "write" or "read"
	host string
	pool *pgxpool.Pool
}

// allPools lists every distinct pgx pool the manager opened, each once: the write
// hosts' WritePools as "write", and as "read" every other pool reads are served from
// (a write host's dedicated read pool, a replica's pool). A pool shared by reads and
// writes counts as "write". Caller holds fm.mu.
func (fm *RuntimeFailoverManager) allPools() []rolePool {
	var pools []rolePool
	seen := make(map[*pgxpool.Pool]bool)
	add := func(role string, p *DatabasePool, pool *pgxpool.Pool) {
		if pool == nil || seen[pool] {
			return
		}
		seen[pool] = true
		pools = append(pools, rolePool{role: role, host: p.host, pool: pool})
	}
	for _, p := range fm.writePools {
		if p.database != nil {
			add("write", p, p.database.WritePool)
		}
	}
	for _, group := range [][]*DatabasePool{fm.writePools, fm.readPools} {
		for _, p := range group {
			if p.database != nil {
				add("read", p, p.database.ReadPool)
			}
		}
	}
	return pools
}

// collectAggregatedPoolStats updates the pool gauges from every pool the manager opened.
func (rd *ResilientDatabase) collectAggregatedPoolStats() {
	rd.reportPools(false)
}

// StartPoolHealthMonitoring starts background monitoring of connection pool health
// for all managed database pools with enhanced metrics collection
func (rd *ResilientDatabase) StartPoolHealthMonitoring(ctx context.Context) {
	rd.failoverManager.healthCheckWg.Add(1)
	// Store local reference to stop channel to avoid race detector warnings
	stopChan := rd.failoverManager.healthCheckStop
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
			case <-stopChan:
				logger.Info("Stopping aggregated pool health monitoring (close signal)", "component", "RESILIENT-FAILOVER")
				return
			case <-ticker.C:
				rd.monitorAggregatedPoolHealth()
			}
		}
	}()
}

// monitorAggregatedPoolHealth updates the pool gauges and checks every pool for exhaustion.
func (rd *ResilientDatabase) monitorAggregatedPoolHealth() {
	rd.reportPools(true)
}

// reportPools sets the sora_db_pool_* gauges per role, summed over every pool the
// manager opened (allPools). With checkExhaustion it also counts and logs the pools
// above 95% utilization and logs a summary per role.
func (rd *ResilientDatabase) reportPools(checkExhaustion bool) {
	rd.failoverManager.mu.RLock()
	pools := rd.failoverManager.allPools()
	rd.failoverManager.mu.RUnlock()

	for _, role := range []string{"write", "read"} {
		var totalConns, idleConns, acquiredConns int32
		var poolCount, exhaustionCount int
		for _, p := range pools {
			if p.role != role {
				continue
			}
			stats := p.pool.Stat()
			poolCount++
			totalConns += stats.TotalConns()
			idleConns += stats.IdleConns()
			acquiredConns += stats.AcquiredConns()

			if checkExhaustion && stats.MaxConns() > 0 {
				utilization := float64(stats.AcquiredConns()) / float64(stats.MaxConns())
				if utilization > 0.95 {
					exhaustionCount++
					logger.Warn("Database pool near exhaustion", "component", "RESILIENT-FAILOVER",
						"type", role, "host", p.host, "utilization_pct", utilization*100)
				}
			}
		}

		metrics.DBPoolTotalConns.WithLabelValues(role).Set(float64(totalConns))
		metrics.DBPoolIdleConns.WithLabelValues(role).Set(float64(idleConns))
		metrics.DBPoolInUseConns.WithLabelValues(role).Set(float64(acquiredConns))

		if !checkExhaustion || poolCount == 0 {
			continue
		}
		if exhaustionCount > 0 {
			metrics.DBPoolExhaustion.WithLabelValues(role).Add(float64(exhaustionCount))
		}
		logger.Info("Pools health status", "component", "RESILIENT-FAILOVER", "type", role, "total_conns", totalConns, "idle", idleConns, "in_use", acquiredConns, "pools", poolCount)
	}
}

// GetOrCreateMailboxByNameWithRetry retrieves a mailbox by name, creating it if it doesn't exist.
// This is more efficient than separate get and create calls as it aims to do it in a single transaction.
func (rd *ResilientDatabase) GetOrCreateMailboxByNameWithRetry(ctx context.Context, AccountID int64, name string) (*db.DBMailbox, error) {
	// Mailbox names are case-insensitive (Option A; matches GetMailboxByName and
	// the UNIQUE(account_id, LOWER(name)) index). Every lookup below folds case so
	// a request for "Inbox"/"archive" resolves to an existing "INBOX"/"Archive"
	// instead of creating a case-variant duplicate. CanonicalMailboxName only
	// normalizes the reserved INBOX spelling so a freshly-created inbox is stored
	// as "INBOX" (RFC 3501 §5.1); all other names keep their as-typed case.
	//
	// The name is checked before anything is created: "Foo/" is "Foo" (RFC 3501
	// §6.3.3), and a name with an empty, "." or ".." level is refused rather than
	// creating a parent such as "x/" or "" on the way, or failing halfway.
	created, err := helpers.MailboxNameToCreate(name)
	if err != nil {
		return nil, fmt.Errorf("mailbox %q: %w", name, err)
	}
	name = helpers.CanonicalMailboxName(created)
	op := func(ctx context.Context, tx pgx.Tx) (any, error) {
		// First, try to get the mailbox within the transaction (case-insensitive).
		var mb db.DBMailbox
		err := tx.QueryRow(ctx, "SELECT id, account_id, name FROM mailboxes WHERE account_id = $1 AND LOWER(name) = LOWER($2) AND deleted_at IS NULL", AccountID, name).Scan(&mb.ID, &mb.AccountID, &mb.Name)
		if err == nil {
			return &mb, nil // Found it, we're done.
		}

		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("failed to get mailbox: %w", err)
		}

		dbLayer := rd.getOperationalDatabaseForOperation(ctx, true)
		parts := strings.Split(name, string(consts.MailboxDelimiter))
		var currentParentID *int64

		if len(parts) > 1 {
			for i := 1; i < len(parts); i++ {
				parentName := strings.Join(parts[:i], string(consts.MailboxDelimiter))
				var pID int64
				err := tx.QueryRow(ctx, "SELECT id FROM mailboxes WHERE account_id = $1 AND LOWER(name) = LOWER($2) AND deleted_at IS NULL", AccountID, parentName).Scan(&pID)
				if err != nil {
					if errors.Is(err, pgx.ErrNoRows) {
						err = dbLayer.CreateMailbox(ctx, tx, AccountID, parentName, currentParentID)
						if err != nil && !errors.Is(err, consts.ErrDBUniqueViolation) {
							return nil, fmt.Errorf("failed to auto-create parent mailbox '%s': %w", parentName, err)
						}
						// Retrieve the parent ID, handles both successful creation and concurrent creation
						err = tx.QueryRow(ctx, "SELECT id FROM mailboxes WHERE account_id = $1 AND LOWER(name) = LOWER($2) AND deleted_at IS NULL", AccountID, parentName).Scan(&pID)
						if err != nil {
							return nil, fmt.Errorf("failed to fetch parent mailbox '%s' after creation: %w", parentName, err)
						}
					} else {
						return nil, fmt.Errorf("failed to check parent mailbox '%s': %w", parentName, err)
					}
				}
				currentParentID = &pID
			}
		}

		// Create the target mailbox
		err = dbLayer.CreateMailbox(ctx, tx, AccountID, name, currentParentID)
		if err != nil && !errors.Is(err, consts.ErrDBUniqueViolation) {
			return nil, fmt.Errorf("failed to create mailbox '%s': %w", name, err)
		}

		// Fetch the newly created (or concurrently created) mailbox (case-insensitive,
		// so a concurrent creator that stored a different case is still found).
		err = tx.QueryRow(ctx, "SELECT id, account_id, name FROM mailboxes WHERE account_id = $1 AND LOWER(name) = LOWER($2) AND deleted_at IS NULL", AccountID, name).Scan(&mb.ID, &mb.AccountID, &mb.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch created mailbox '%s': %w", name, err)
		}

		// Ensure the mailbox is subscribed, as expected by importer and LMTP create.
		// Subscriptions are name-based (migration 000046), so record it there rather
		// than on the vestigial mailboxes.subscribed column.
		_, err = tx.Exec(ctx, `
			INSERT INTO subscriptions (account_id, mailbox_name)
			VALUES ($1, $2)
			ON CONFLICT (account_id, LOWER(mailbox_name)) DO NOTHING
		`, mb.AccountID, mb.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to subscribe mailbox '%s': %w", name, err)
		}

		logger.Info("Created or found mailbox via upsert", "name", name)
		return &mb, nil
	}

	// Use the existing resilient transaction helper.
	result, err := rd.executeWriteInTxWithRetry(ctx, importExportRetryConfig, timeoutAdmin, op)
	if err != nil {
		return nil, err
	}

	return result.(*db.DBMailbox), nil
}

// QRESYNC Support (RFC 7162)
// These methods provide efficient mailbox resynchronization for IMAP clients.

// GetVanishedUIDsWithRetry returns UIDs that were expunged between sinceModSeq and untilModSeq.
func (rd *ResilientDatabase) GetVanishedUIDsWithRetry(ctx context.Context, mailboxID int64, sinceModSeq, untilModSeq uint64) ([]imap.UID, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetVanishedUIDs(ctx, mailboxID, sinceModSeq, untilModSeq)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.([]imap.UID), nil
}

// GetMessagesChangedSinceWithRetry returns messages that were created or modified after sinceModSeq.
func (rd *ResilientDatabase) GetMessagesChangedSinceWithRetry(ctx context.Context, mailboxID int64, sinceModSeq uint64) ([]db.QResyncModifiedMessage, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetMessagesChangedSince(ctx, mailboxID, sinceModSeq)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.([]db.QResyncModifiedMessage), nil
}

// GetVanishedUIDsForFetchWithRetry returns vanished UIDs for FETCH VANISHED modifier.
func (rd *ResilientDatabase) GetVanishedUIDsForFetchWithRetry(ctx context.Context, mailboxID int64, sinceModSeq uint64) ([]imap.UID, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetVanishedUIDsForFetch(ctx, mailboxID, sinceModSeq)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.([]imap.UID), nil
}

// ValidateQResyncUIDValidityWithRetry checks if the client's UIDValidity matches the current mailbox.
func (rd *ResilientDatabase) ValidateQResyncUIDValidityWithRetry(ctx context.Context, mailboxID int64, clientUIDValidity uint32) (bool, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).ValidateQResyncUIDValidity(ctx, mailboxID, clientUIDValidity)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return false, err
	}
	return result.(bool), nil
}

// GetActiveUIDsInSetWithRetry returns the active UIDs in the mailbox that fall within the given UIDSet.
func (rd *ResilientDatabase) GetActiveUIDsInSetWithRetry(ctx context.Context, mailboxID int64, uidSet imap.UIDSet) ([]imap.UID, error) {
	op := func(ctx context.Context) (any, error) {
		return rd.getOperationalDatabaseForOperation(ctx, false).GetActiveUIDsInSet(ctx, mailboxID, uidSet)
	}
	result, err := rd.executeReadWithRetry(ctx, readRetryConfig, timeoutRead, op)
	if err != nil {
		return nil, err
	}
	return result.([]imap.UID), nil
}
