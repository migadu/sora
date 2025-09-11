package db

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/metrics"
)

//go:embed schema.sql
var schema string

// HostHealth tracks the health status of a database host
type HostHealth struct {
	Host             string
	IsHealthy        atomic.Bool
	LastHealthCheck  time.Time
	ConsecutiveFails int64
	mu               sync.RWMutex
}

// FailoverManager manages host selection and failover for database connections
type FailoverManager struct {
	hosts        []*HostHealth
	currentIndex atomic.Int64
	poolType     string
	// Store endpoint config to build health check connection strings
	endpointConfig *config.DatabaseEndpointConfig
}

// PoolHealthStatus represents the health status of a connection pool
type PoolHealthStatus struct {
	IsHealthy           bool
	TotalConnections    int32
	IdleConnections     int32
	AcquiredConnections int32
	MaxConnections      int32
	AcquireCount        int64
	AcquireDuration     time.Duration
	NewConnections      int64
	MaxLifetimeDestroy  int64
	MaxIdleDestroy      int64
	ConstructingConns   int32
}

type Database struct {
	WritePool     *pgxpool.Pool    // Write operations pool
	ReadPool      *pgxpool.Pool    // Read operations pool
	WriteFailover *FailoverManager // Failover manager for write operations
	ReadFailover  *FailoverManager // Failover manager for read operations
}

// DatabasePoolConfig holds configuration for the database connection pool.
type DatabasePoolConfig struct {
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

// NewDatabase initializes a new SQL database connection using default pool settings.
func NewDatabase(ctx context.Context, host, port, user, password, dbname string, tlsMode bool, logQueries bool) (*Database, error) {
	return NewDatabaseWithPoolConfig(ctx, host, port, user, password, dbname, tlsMode, logQueries, nil)
}

func NewDatabaseWithPoolConfig(ctx context.Context, host, port, user, password, dbname string, tlsMode bool, logQueries bool, poolConfig *DatabasePoolConfig) (*Database, error) {
	sslMode := "disable"
	if tlsMode {
		sslMode = "require"
	}

	connString := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		user, password, host, port, dbname, sslMode)

	log.Printf("[DB] connecting to database: postgres://%s@%s:%s/%s?sslmode=%s",
		user, host, port, dbname, sslMode)

	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		log.Fatalf("unable to parse connection string: %v", err)
	}

	if logQueries {
		config.ConnConfig.Tracer = &CustomTracer{}
	}

	if poolConfig != nil {
		config.MaxConns = poolConfig.MaxConns
		config.MinConns = poolConfig.MinConns
		config.MaxConnLifetime = poolConfig.MaxConnLifetime
		config.MaxConnIdleTime = poolConfig.MaxConnIdleTime
	}

	dbPool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %v", err)
	}

	if err := dbPool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect to the database: %v", err)
	}

	db := &Database{
		WritePool: dbPool,
		ReadPool:  dbPool, // Default to same pool if no read/write split
	}

	if err := db.migrate(ctx); err != nil {
		return nil, err
	}

	return db, nil
}

func (db *Database) Close() {
	if db.WritePool != nil {
		db.WritePool.Close()
	}
	if db.ReadPool != nil && db.ReadPool != db.WritePool {
		db.ReadPool.Close()
	}
}


// GetWritePool returns the connection pool for write operations
func (db *Database) GetWritePool() *pgxpool.Pool {
	return db.WritePool
}

// GetReadPool returns the connection pool for read operations
func (db *Database) GetReadPool() *pgxpool.Pool {
	return db.ReadPool
}

// GetReadPoolWithContext returns the appropriate pool for read operations, considering session pinning
func (db *Database) GetReadPoolWithContext(ctx context.Context) *pgxpool.Pool {
	// Check if the context signals to use the master DB (session pinning)
	if useMaster, ok := ctx.Value(consts.UseMasterDBKey).(bool); ok && useMaster {
		return db.WritePool // Use write pool for read-after-write consistency
	}
	return db.ReadPool
}

func (db *Database) migrate(ctx context.Context) error {
	_, err := db.WritePool.Exec(ctx, schema)
	return err
}

// GetPoolHealth returns the health status of database connection pools
func (db *Database) GetPoolHealth() map[string]*PoolHealthStatus {
	result := make(map[string]*PoolHealthStatus)

	if db.WritePool != nil {
		stats := db.WritePool.Stat()
		result["write"] = &PoolHealthStatus{
			TotalConnections:    stats.TotalConns(),
			IdleConnections:     stats.IdleConns(),
			AcquiredConnections: stats.AcquiredConns(),
			MaxConnections:      stats.MaxConns(),
			AcquireCount:        stats.AcquireCount(),
			AcquireDuration:     stats.AcquireDuration(),
			NewConnections:      stats.NewConnsCount(),
			MaxLifetimeDestroy:  stats.MaxLifetimeDestroyCount(),
			MaxIdleDestroy:      stats.MaxIdleDestroyCount(),
			ConstructingConns:   stats.ConstructingConns(),
		}

		// Pool is considered unhealthy if:
		// 1. Too many connections are in use (>90% utilization)
		// 2. Acquire duration is too high (>5 seconds average)
		// 3. Too many connections are constructing (>20% of max)
		maxConns := float64(stats.MaxConns())
		acquiredConns := float64(stats.AcquiredConns())
		constructingConns := float64(stats.ConstructingConns())

		result["write"].IsHealthy = true
		if acquiredConns/maxConns > 0.90 {
			result["write"].IsHealthy = false
			log.Printf("[DB-HEALTH] Write pool unhealthy: high utilization (%.1f%%)", (acquiredConns/maxConns)*100)
		}
		if stats.AcquireDuration() > 5*time.Second {
			result["write"].IsHealthy = false
			log.Printf("[DB-HEALTH] Write pool unhealthy: slow acquire duration (%v)", stats.AcquireDuration())
		}
		if constructingConns/maxConns > 0.20 {
			result["write"].IsHealthy = false
			log.Printf("[DB-HEALTH] Write pool unhealthy: too many constructing connections (%.1f%%)", (constructingConns/maxConns)*100)
		}
	}

	if db.ReadPool != nil && db.ReadPool != db.WritePool {
		stats := db.ReadPool.Stat()
		result["read"] = &PoolHealthStatus{
			TotalConnections:    stats.TotalConns(),
			IdleConnections:     stats.IdleConns(),
			AcquiredConnections: stats.AcquiredConns(),
			MaxConnections:      stats.MaxConns(),
			AcquireCount:        stats.AcquireCount(),
			AcquireDuration:     stats.AcquireDuration(),
			NewConnections:      stats.NewConnsCount(),
			MaxLifetimeDestroy:  stats.MaxLifetimeDestroyCount(),
			MaxIdleDestroy:      stats.MaxIdleDestroyCount(),
			ConstructingConns:   stats.ConstructingConns(),
		}

		maxConns := float64(stats.MaxConns())
		acquiredConns := float64(stats.AcquiredConns())
		constructingConns := float64(stats.ConstructingConns())

		result["read"].IsHealthy = true
		if acquiredConns/maxConns > 0.90 {
			result["read"].IsHealthy = false
			log.Printf("[DB-HEALTH] Read pool unhealthy: high utilization (%.1f%%)", (acquiredConns/maxConns)*100)
		}
		if stats.AcquireDuration() > 5*time.Second {
			result["read"].IsHealthy = false
			log.Printf("[DB-HEALTH] Read pool unhealthy: slow acquire duration (%v)", stats.AcquireDuration())
		}
		if constructingConns/maxConns > 0.20 {
			result["read"].IsHealthy = false
			log.Printf("[DB-HEALTH] Read pool unhealthy: too many constructing connections (%.1f%%)", (constructingConns/maxConns)*100)
		}
	}

	return result
}


// GetWriteFailoverStats returns failover statistics for write operations
func (db *Database) GetWriteFailoverStats() []map[string]interface{} {
	if db.WriteFailover == nil {
		return nil
	}
	return db.WriteFailover.GetHostStats()
}

// GetReadFailoverStats returns failover statistics for read operations
func (db *Database) GetReadFailoverStats() []map[string]interface{} {
	if db.ReadFailover == nil {
		return nil
	}
	return db.ReadFailover.GetHostStats()
}

// StartFailoverHealthChecks starts background health checking for database hosts
func (db *Database) StartFailoverHealthChecks(ctx context.Context, interval time.Duration) {
	if interval == 0 {
		interval = 30 * time.Second // Default health check interval
	}

	// Start health checking for write hosts
	if db.WriteFailover != nil && len(db.WriteFailover.hosts) > 1 {
		go db.runHealthChecks(ctx, db.WriteFailover, interval)
	}

	// Start health checking for read hosts (if different from write)
	if db.ReadFailover != nil && db.ReadFailover != db.WriteFailover && len(db.ReadFailover.hosts) > 1 {
		go db.runHealthChecks(ctx, db.ReadFailover, interval)
	}
}

// runHealthChecks performs periodic health checks on database hosts
func (db *Database) runHealthChecks(ctx context.Context, fm *FailoverManager, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("[DB-%s-HEALTH] Starting health checks every %v", fm.poolType, interval)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[DB-%s-HEALTH] Stopping health checks", fm.poolType)
			return
		case <-ticker.C:
			db.performHealthCheck(ctx, fm)
		}
	}
}

// performHealthCheck checks the health of all hosts in a failover manager
func (db *Database) performHealthCheck(ctx context.Context, fm *FailoverManager) {
	for _, host := range fm.hosts {
		// Only check unhealthy hosts or hosts that haven't been checked recently
		if host.IsHealthy.Load() {
			continue // Skip healthy hosts to avoid unnecessary load
		}

		host.mu.RLock()
		lastCheck := host.LastHealthCheck
		consecutiveFails := host.ConsecutiveFails
		host.mu.RUnlock()

		// Implement exponential backoff for health checks
		backoffDuration := time.Duration(1<<minInt64(consecutiveFails, 6)) * time.Second
		if time.Since(lastCheck) < backoffDuration {
			continue // Too soon to check again
		}

		go func(h *HostHealth) {
			db.checkHostHealth(ctx, fm, h)
		}(host)
	}
}

// checkHostHealth performs a health check on a specific host
func (db *Database) checkHostHealth(ctx context.Context, fm *FailoverManager, host *HostHealth) {
	// Create a quick health check connection with timeout
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	actualHost := host.Host
	if !strings.Contains(host.Host, ":") {
		actualHost = fmt.Sprintf("%s:5432", host.Host)
	}

	// Build a connection string for the health check.
	// This uses the credentials from the config but connects to the 'postgres'
	// database with a short timeout. This is more secure and flexible than a
	// hardcoded user/password/sslmode.
	endpoint := fm.endpointConfig
	sslMode := "disable"
	if endpoint.TLSMode {
		sslMode = "require"
	}
	connString := fmt.Sprintf("postgres://%s:%s@%s/postgres?sslmode=%s&connect_timeout=3",
		endpoint.User, endpoint.Password, actualHost, sslMode)

	conn, err := pgx.Connect(checkCtx, connString)
	if err != nil {
		fm.MarkHostUnhealthy(host.Host, fmt.Errorf("health check failed: %w", err))
		return
	}
	defer conn.Close(checkCtx)
	// Simple ping query
	var result int
	err = conn.QueryRow(checkCtx, "SELECT 1").Scan(&result)
	if err != nil {
		fm.MarkHostUnhealthy(host.Host, fmt.Errorf("health check query failed: %w", err))
		return
	}
	// Host is healthy
	fm.MarkHostHealthy(host.Host)
}

// NewDatabaseFromConfig creates a new database connection with read/write split configuration
func NewDatabaseFromConfig(ctx context.Context, dbConfig *config.DatabaseConfig) (*Database, error) {
	if dbConfig.Write == nil {
		return nil, fmt.Errorf("write database configuration is required")
	}

	// Create write failover manager and pool
	writeFailover := NewFailoverManager(dbConfig.Write, "write")
	writePool, err := createPoolFromEndpointWithFailover(ctx, dbConfig.Write, dbConfig.LogQueries, "write", writeFailover)
	if err != nil {
		return nil, fmt.Errorf("failed to create write pool: %v", err)
	}

	// Create read pool and failover manager
	var readPool *pgxpool.Pool
	var readFailover *FailoverManager
	if dbConfig.Read != nil {
		readFailover = NewFailoverManager(dbConfig.Read, "read")
		readPool, err = createPoolFromEndpointWithFailover(ctx, dbConfig.Read, dbConfig.LogQueries, "read", readFailover)
		if err != nil {
			writePool.Close() // Clean up write pool on error
			return nil, fmt.Errorf("failed to create read pool: %v", err)
		}
	} else {
		// If no read config specified, use write pool for reads
		log.Printf("[DB] No read configuration specified, using write pool for read operations")
		readPool = writePool
		readFailover = writeFailover // Share the same failover manager
	}

	db := &Database{
		WritePool:     writePool,
		ReadPool:      readPool,
		WriteFailover: writeFailover,
		ReadFailover:  readFailover,
	}

	if err := db.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

// createPoolFromEndpointWithFailover creates a connection pool with an existing failover manager
func createPoolFromEndpointWithFailover(ctx context.Context, endpoint *config.DatabaseEndpointConfig, logQueries bool, poolType string, failoverManager *FailoverManager) (*pgxpool.Pool, error) {
	if len(endpoint.Hosts) == 0 {
		return nil, fmt.Errorf("at least one host must be specified")
	}

	// Try to create connection pool with provided failover manager
	var lastErr error
	maxAttempts := len(endpoint.Hosts)

	for attempt := 0; attempt < maxAttempts; attempt++ {
		selectedHost, err := failoverManager.GetNextHealthyHost()
		if err != nil {
			return nil, fmt.Errorf("failed to select host: %w", err)
		}

		// Handle host:port combination
		actualHost := selectedHost
		if !strings.Contains(selectedHost, ":") {
			port := 5432 // Default PostgreSQL port
			if endpoint.Port != nil {
				var p int64
				var parseErr error
				switch v := endpoint.Port.(type) {
				case string:
					p, parseErr = strconv.ParseInt(v, 10, 32)
					if parseErr != nil {
						return nil, fmt.Errorf("invalid string for port: %q", v)
					}
				case int:
					p = int64(v)
				case int64:
					p = v
				default:
					return nil, fmt.Errorf("invalid type for port: %T", v)
				}
				port = int(p)
			}
			if port <= 0 || port > 65535 {
				return nil, fmt.Errorf("port number %d is out of the valid range (1-65535)", port)
			}
			actualHost = fmt.Sprintf("%s:%d", selectedHost, port)
		}

		sslMode := "disable"
		if endpoint.TLSMode {
			sslMode = "require"
		}

		connString := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s",
			endpoint.User, endpoint.Password, actualHost, endpoint.Name, sslMode)

		config, err := pgxpool.ParseConfig(connString)
		if err != nil {
			lastErr = fmt.Errorf("unable to parse connection string: %v", err)
			failoverManager.MarkHostUnhealthy(selectedHost, lastErr)
			continue
		}

		if logQueries {
			config.ConnConfig.Tracer = &CustomTracer{}
		}

		// Apply pool configuration
		if endpoint.MaxConns > 0 {
			config.MaxConns = int32(endpoint.MaxConns)
		}
		if endpoint.MinConns > 0 {
			config.MinConns = int32(endpoint.MinConns)
		}

		if endpoint.MaxConnLifetime != "" {
			lifetime, err := endpoint.GetMaxConnLifetime()
			if err != nil {
				lastErr = fmt.Errorf("invalid max_conn_lifetime: %v", err)
				failoverManager.MarkHostUnhealthy(selectedHost, lastErr)
				continue
			}
			config.MaxConnLifetime = lifetime
		}

		if endpoint.MaxConnIdleTime != "" {
			idleTime, err := endpoint.GetMaxConnIdleTime()
			if err != nil {
				lastErr = fmt.Errorf("invalid max_conn_idle_time: %v", err)
				failoverManager.MarkHostUnhealthy(selectedHost, lastErr)
				continue
			}
			config.MaxConnIdleTime = idleTime
		}

		dbPool, err := pgxpool.NewWithConfig(ctx, config)
		if err != nil {
			lastErr = fmt.Errorf("failed to create connection pool: %v", err)
			failoverManager.MarkHostUnhealthy(selectedHost, lastErr)
			continue
		}

		if err := dbPool.Ping(ctx); err != nil {
			dbPool.Close()
			lastErr = fmt.Errorf("failed to connect to the database: %v", err)
			failoverManager.MarkHostUnhealthy(selectedHost, lastErr)
			continue
		}

		// Connection successful
		failoverManager.MarkHostHealthy(selectedHost)
		log.Printf("[DB] %s pool created successfully with failover - host: %s", poolType, actualHost)
		return dbPool, nil
	}

	return nil, fmt.Errorf("failed to connect to any %s database host after %d attempts: %w", poolType, maxAttempts, lastErr)
}

// NewFailoverManager creates a new failover manager for the given hosts
func NewFailoverManager(endpointConfig *config.DatabaseEndpointConfig, poolType string) *FailoverManager {
	fm := &FailoverManager{
		hosts:          make([]*HostHealth, len(endpointConfig.Hosts)),
		poolType:       poolType,
		endpointConfig: endpointConfig,
	}

	for i, host := range endpointConfig.Hosts {
		hh := &HostHealth{
			Host: host,
		}
		hh.IsHealthy.Store(true) // Start with healthy assumption
		hh.LastHealthCheck = time.Now()
		fm.hosts[i] = hh
	}

	return fm
}

// GetNextHealthyHost returns the next healthy host using round-robin with failover
func (fm *FailoverManager) GetNextHealthyHost() (string, error) {
	if len(fm.hosts) == 0 {
		return "", fmt.Errorf("no hosts configured")
	}

	// If only one host, return it regardless of health
	if len(fm.hosts) == 1 {
		return fm.hosts[0].Host, nil
	}

	maxAttempts := len(fm.hosts) * 2 // Try each host twice
	startIndex := fm.currentIndex.Load()

	for attempt := 0; attempt < maxAttempts; attempt++ {
		index := (startIndex + int64(attempt)) % int64(len(fm.hosts))
		host := fm.hosts[index]

		if host.IsHealthy.Load() {
			fm.currentIndex.Store((index + 1) % int64(len(fm.hosts)))
			return host.Host, nil
		}

		// Check if we should retry an unhealthy host (circuit breaker pattern)
		host.mu.RLock()
		lastCheck := host.LastHealthCheck
		consecutiveFails := host.ConsecutiveFails
		host.mu.RUnlock()

		// Exponential backoff: wait longer after more failures
		backoffDuration := time.Duration(1<<minInt64(consecutiveFails, 6)) * time.Second
		if time.Since(lastCheck) > backoffDuration {
			log.Printf("[DB-%s-FAILOVER] Retrying potentially recovered host: %s (fails: %d, backoff: %v)",
				fm.poolType, host.Host, consecutiveFails, backoffDuration)
			fm.currentIndex.Store((index + 1) % int64(len(fm.hosts)))
			return host.Host, nil
		}
	}

	// All hosts are unhealthy, return the first one and hope for the best
	fallbackHost := fm.hosts[0].Host
	log.Printf("[DB-%s-FAILOVER] WARNING: All hosts appear unhealthy and are within their backoff period. "+
		"Falling back to the primary host (%s) as a last resort.",
		fm.poolType, fallbackHost)
	return fallbackHost, nil
}

// MarkHostHealthy marks a host as healthy
func (fm *FailoverManager) MarkHostHealthy(host string) {
	for _, h := range fm.hosts {
		if h.Host == host {
			wasUnhealthy := !h.IsHealthy.Load()
			h.IsHealthy.Store(true)
			h.mu.Lock()
			h.ConsecutiveFails = 0
			h.LastHealthCheck = time.Now()
			h.mu.Unlock()

			if wasUnhealthy {
				log.Printf("[DB-%s-FAILOVER] Host %s marked as healthy", fm.poolType, host)
			}
			break
		}
	}
}

// MarkHostUnhealthy marks a host as unhealthy
func (fm *FailoverManager) MarkHostUnhealthy(host string, err error) {
	for _, h := range fm.hosts {
		if h.Host == host {
			wasHealthy := h.IsHealthy.Load()
			h.IsHealthy.Store(false)
			h.mu.Lock()
			h.ConsecutiveFails++
			h.LastHealthCheck = time.Now()
			fails := h.ConsecutiveFails
			h.mu.Unlock()

			if wasHealthy {
				log.Printf("[DB-%s-FAILOVER] Host %s marked as unhealthy (fails: %d, error: %v)",
					fm.poolType, host, fails, err)
			}
			break
		}
	}
}

// GetHostStats returns health statistics for all hosts
func (fm *FailoverManager) GetHostStats() []map[string]interface{} {
	stats := make([]map[string]interface{}, len(fm.hosts))
	for i, h := range fm.hosts {
		h.mu.RLock()
		stats[i] = map[string]interface{}{
			"host":              h.Host,
			"healthy":           h.IsHealthy.Load(),
			"last_health_check": h.LastHealthCheck,
			"consecutive_fails": h.ConsecutiveFails,
		}
		h.mu.RUnlock()
	}
	return stats
}

// minInt64 helper function for int64 values
func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// measuredTx wraps a pgx.Tx to record metrics on commit or rollback.
type measuredTx struct {
	pgx.Tx
	start time.Time
}

// BeginTx starts a new transaction and wraps it for metric collection.
func (db *Database) BeginTx(ctx context.Context) (pgx.Tx, error) {
	tx, err := db.GetWritePool().Begin(ctx)
	if err != nil {
		return nil, err
	}

	return &measuredTx{
		Tx:    tx,
		start: time.Now(),
	}, nil
}

func (mtx *measuredTx) Commit(ctx context.Context) error {
	err := mtx.Tx.Commit(ctx)
	if err == nil {
		metrics.DBTransactionsTotal.WithLabelValues("commit").Inc()
	}
	metrics.DBTransactionDuration.Observe(time.Since(mtx.start).Seconds())
	return err
}

func (mtx *measuredTx) Rollback(ctx context.Context) error {
	err := mtx.Tx.Rollback(ctx)
	// We count a rollback attempt even if the rollback itself fails.
	metrics.DBTransactionsTotal.WithLabelValues("rollback").Inc()
	metrics.DBTransactionDuration.Observe(time.Since(mtx.start).Seconds())
	return err
}
