package resilient

import (
	"context"
	"errors"
	"fmt"
	"log"
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

// RuntimeFailoverManager manages multiple database pools and handles failover
type RuntimeFailoverManager struct {
	writePools      []*DatabasePool
	readPools       []*DatabasePool
	currentWriteIdx atomic.Int64
	currentReadIdx  atomic.Int64
	config          *config.DatabaseConfig
	healthCheckStop chan struct{}
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
		log.Printf("[RESILIENT-FAILOVER] Database query circuit breaker '%s' changed from %s to %s", name, from, to)
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
		log.Printf("[RESILIENT-FAILOVER] Database write circuit breaker '%s' changed from %s to %s", name, from, to)
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
			log.Printf("WARN: Invalid global write_timeout, using default 10s: %v", err)
			timeout = 15 * time.Second
		}
	case timeoutSearch:
		timeout, err = rd.config.GetSearchTimeout()
		if err != nil {
			log.Printf("WARN: Invalid global search_timeout, using default: %v", err)
			timeout = 60 * time.Second
		}
	case timeoutAuth:
		// Auth operations should be fast - use write timeout as base, but shorter
		timeout, err = rd.config.GetWriteTimeout()
		if err != nil {
			log.Printf("WARN: Invalid global write_timeout for auth, using default 10s: %v", err)
			timeout = 10 * time.Second
		} else if timeout > 10*time.Second {
			// Cap auth timeout to be reasonably fast
			timeout = 10 * time.Second
		}
	case timeoutAdmin:
		// Admin operations can be longer (imports, user creation)
		timeout, err = rd.config.GetSearchTimeout() // Use search timeout as base
		if err != nil {
			log.Printf("WARN: Invalid global search_timeout for admin, using default 45s: %v", err)
			timeout = 45 * time.Second
		}
		timeout = time.Duration(float64(timeout) * 0.75) // Admin ops get 75% of search timeout
	default: // timeoutRead
		timeout, err = rd.config.GetQueryTimeout()
		if err != nil {
			log.Printf("WARN: Invalid global query_timeout, using default: %v", err)
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
				log.Printf("WARN: Invalid endpoint query_timeout, using global/default: %v", endpointErr)
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
			log.Printf("Retrying query due to retryable error: %v", cbErr)
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
			log.Printf("Retrying BeginTx due to retryable error: %v", cbErr)
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
		config:          config,
		healthCheckStop: make(chan struct{}),
	}

	// Create database pools for all write hosts
	if config.Write != nil && len(config.Write.Hosts) > 0 {
		for i, host := range config.Write.Hosts {
			// Only run migrations and acquire lock for the very first write pool.
			isFirstPool := (i == 0)
			pool, err := createDatabasePool(ctx, host, config.Write, config.LogQueries, "write", runMigrations && isFirstPool, isFirstPool)
			if err != nil {
				log.Printf("[RESILIENT-FAILOVER] Failed to create write pool for host %s: %v", host, err)
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
		for i, host := range config.Read.Hosts {
			// Never run migrations or acquire lock for read pools.
			pool, err := createDatabasePool(ctx, host, config.Read, config.LogQueries, "read", false, false)
			if err != nil {
				log.Printf("[RESILIENT-FAILOVER] Failed to create read pool for host %s: %v", host, err)
				continue
			}

			dbPool := &DatabasePool{
				database: pool,
				host:     host,
			}
			dbPool.isHealthy.Store(true) // Start as healthy

			manager.readPools = append(manager.readPools, dbPool)

			// First pool becomes the current one
			if i == 0 {
				manager.currentReadIdx.Store(0)
			}
		}
	}

	// Fallback: if no read pools, use write pools for reads
	if len(manager.readPools) == 0 && len(manager.writePools) > 0 {
		log.Printf("[RESILIENT-FAILOVER] No read pools configured, using write pools for read operations")
		manager.readPools = manager.writePools
		manager.currentReadIdx.Store(manager.currentWriteIdx.Load())
	}

	if len(manager.writePools) == 0 {
		return nil, fmt.Errorf("no healthy database pools available")
	}

	log.Printf("[RESILIENT-FAILOVER] Created runtime failover manager with %d write pools and %d read pools",
		len(manager.writePools), len(manager.readPools))
	return manager, nil
}

// createDatabasePool creates a single database connection pool
func createDatabasePool(ctx context.Context, host string, endpointConfig *config.DatabaseEndpointConfig, logQueries bool, poolType string, runMigrations bool, acquireLock bool) (*db.Database, error) {
	// Create a temporary config for this single host
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
				log.Printf("[RESILIENT-FAILOVER] Switched write operations from unhealthy pool %s to healthy pool %s", pools[currentIdx].host, pools[nextIdx].host)
			} else {
				rd.failoverManager.currentReadIdx.Store(int64(nextIdx))
				log.Printf("[RESILIENT-FAILOVER] Switched read operations from unhealthy pool %s to healthy pool %s", pools[currentIdx].host, pools[nextIdx].host)
			}
			return pools[nextIdx].database
		}
	}

	// If we get here, no healthy pools were found. Return the current (unhealthy) pool as a last resort.
	opType := "read"
	if isWrite {
		opType = "write"
	}
	log.Printf("[RESILIENT-FAILOVER] WARNING: No healthy %s database pools available. Continuing to use unhealthy pool %s as a last resort.", opType, pools[currentIdx].host)
	return pools[currentIdx].database
}

// startRuntimeHealthChecking starts background health checking for all pools
func (rd *ResilientDatabase) startRuntimeHealthChecking(ctx context.Context) {
	if rd.failoverManager == nil {
		return
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Printf("[RESILIENT-FAILOVER] Started background health checking")

	for {
		select {
		case <-ctx.Done():
			log.Printf("[RESILIENT-FAILOVER] Stopped background health checking")
			return
		case <-rd.failoverManager.healthCheckStop:
			log.Printf("[RESILIENT-FAILOVER] Stopped background health checking")
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
}

// checkPoolHealth checks the health of a single pool
func (rd *ResilientDatabase) checkPoolHealth(ctx context.Context, pool *DatabasePool, poolType string) {
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := pool.database.WritePool.Ping(healthCtx)
	wasHealthy := pool.isHealthy.Load()
	isHealthyNow := (err == nil)

	if wasHealthy != isHealthyNow {
		pool.isHealthy.Store(isHealthyNow)
		if isHealthyNow {
			log.Printf("[RESILIENT-FAILOVER] %s database pool recovered: %s", poolType, pool.host)
		} else {
			log.Printf("[RESILIENT-FAILOVER] %s database pool failed health check: %s (error: %v)", poolType, pool.host, err)
			pool.lastFailure.Store(time.Now().Unix())
			pool.failCount.Add(1)
		}
	}
}

// StartPoolMetrics starts a goroutine that periodically collects connection pool metrics
// from all managed database pools (both read and write) and exposes them via Prometheus
func (rd *ResilientDatabase) StartPoolMetrics(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
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
	go func() {
		ticker := time.NewTicker(30 * time.Second) // Align with existing health check interval
		defer ticker.Stop()

		log.Printf("[RESILIENT-FAILOVER] Starting aggregated pool health monitoring every 30s")

		for {
			select {
			case <-ctx.Done():
				log.Printf("[RESILIENT-FAILOVER] Stopping aggregated pool health monitoring")
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
					log.Printf("[RESILIENT-FAILOVER] WARNING: %s pool %s near exhaustion (%.1f%% utilization)",
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

	log.Printf("[RESILIENT-FAILOVER] %s pools health: %d total conns, %d idle, %d in-use across %d pools",
		poolType, totalConns, idleConns, acquiredConns, len(pools))
}
