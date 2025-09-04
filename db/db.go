package db

import (
	"context"
	_ "embed"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/metrics"
)

//go:embed schema.sql
var schema string

type Database struct {
	WritePool *pgxpool.Pool // Write operations pool
	ReadPool  *pgxpool.Pool // Read operations pool
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

// StartPoolMetrics starts a goroutine that periodically collects connection pool metrics
func (db *Database) StartPoolMetrics(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				db.collectPoolStats()
			}
		}
	}()
}

// collectPoolStats gathers stats from both read and write pools and updates metrics.
func (d *Database) collectPoolStats() {
	if d.WritePool != nil {
		stats := d.WritePool.Stat()
		metrics.DBPoolTotalConns.WithLabelValues("write").Set(float64(stats.TotalConns()))
		metrics.DBPoolIdleConns.WithLabelValues("write").Set(float64(stats.IdleConns()))
		metrics.DBPoolInUseConns.WithLabelValues("write").Set(float64(stats.AcquiredConns()))
	}
	if d.ReadPool != nil {
		stats := d.ReadPool.Stat()
		metrics.DBPoolTotalConns.WithLabelValues("read").Set(float64(stats.TotalConns()))
		metrics.DBPoolIdleConns.WithLabelValues("read").Set(float64(stats.IdleConns()))
		metrics.DBPoolInUseConns.WithLabelValues("read").Set(float64(stats.AcquiredConns()))
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

// NewDatabaseFromConfig creates a new database connection with read/write split configuration
func NewDatabaseFromConfig(ctx context.Context, dbConfig *config.DatabaseConfig) (*Database, error) {
	if dbConfig.Write == nil {
		return nil, fmt.Errorf("write database configuration is required")
	}

	// Create write pool
	writePool, err := createPoolFromEndpoint(ctx, dbConfig.Write, dbConfig.LogQueries, "write")
	if err != nil {
		return nil, fmt.Errorf("failed to create write pool: %v", err)
	}

	// Create read pool
	var readPool *pgxpool.Pool
	if dbConfig.Read != nil {
		readPool, err = createPoolFromEndpoint(ctx, dbConfig.Read, dbConfig.LogQueries, "read")
		if err != nil {
			writePool.Close() // Clean up write pool on error
			return nil, fmt.Errorf("failed to create read pool: %v", err)
		}
	} else {
		// If no read config specified, use write pool for reads
		log.Printf("[DB] No read configuration specified, using write pool for read operations")
		readPool = writePool
	}

	db := &Database{
		WritePool: writePool,
		ReadPool:  readPool,
	}

	if err := db.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}

	return db, nil
}

// createPoolFromEndpoint creates a connection pool from an endpoint configuration
func createPoolFromEndpoint(ctx context.Context, endpoint *config.DatabaseEndpointConfig, logQueries bool, poolType string) (*pgxpool.Pool, error) {
	if len(endpoint.Hosts) == 0 {
		return nil, fmt.Errorf("at least one host must be specified")
	}

	// For now, randomly select one host. In the future, this could implement load balancing
	selectedHost := endpoint.Hosts[rand.Intn(len(endpoint.Hosts))]

	// Handle host:port combination
	// Priority: 1) host:port in hosts array, 2) separate port field, 3) default 5432
	if !strings.Contains(selectedHost, ":") {
		var portStr string
		if endpoint.Port != nil {
			switch v := endpoint.Port.(type) {
			case string:
				portStr = v
			case int:
				portStr = strconv.Itoa(v)
			case int64: // TOML parsers often use int64 for numbers
				portStr = strconv.FormatInt(v, 10)
			default:
				return nil, fmt.Errorf("invalid type for port: %T", v)
			}
		}
		if portStr == "" {
			portStr = "5432" // Default PostgreSQL port
		}

		// Validate port is a valid integer
		if port, err := strconv.Atoi(portStr); err != nil {
			return nil, fmt.Errorf("invalid port value '%s': %v", portStr, err)
		} else {
			selectedHost = fmt.Sprintf("%s:%d", selectedHost, port)
		}
	}

	sslMode := "disable"
	if endpoint.TLSMode {
		sslMode = "require"
	}

	// Build connection string
	connString := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s",
		endpoint.User, endpoint.Password, selectedHost, endpoint.Name, sslMode)

	log.Printf("[DB] connecting to %s database: postgres://%s@%s/%s?sslmode=%s (hosts: %v)",
		poolType, endpoint.User, selectedHost, endpoint.Name, sslMode, endpoint.Hosts)

	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse connection string: %v", err)
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
			return nil, fmt.Errorf("invalid max_conn_lifetime: %v", err)
		}
		config.MaxConnLifetime = lifetime
	}

	if endpoint.MaxConnIdleTime != "" {
		idleTime, err := endpoint.GetMaxConnIdleTime()
		if err != nil {
			return nil, fmt.Errorf("invalid max_conn_idle_time: %v", err)
		}
		config.MaxConnIdleTime = idleTime
	}

	dbPool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %v", err)
	}

	if err := dbPool.Ping(ctx); err != nil {
		dbPool.Close()
		return nil, fmt.Errorf("failed to connect to the database: %v", err)
	}

	log.Printf("[DB] %s pool created successfully - max_conns: %d, min_conns: %d, max_lifetime: %s, max_idle: %s",
		poolType, dbPool.Config().MaxConns, dbPool.Config().MinConns,
		dbPool.Config().MaxConnLifetime, dbPool.Config().MaxConnIdleTime)

	return dbPool, nil
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

// Database timing helpers for critical operations

// TimedQueryRow wraps QueryRow with duration metrics
func (db *Database) TimedQueryRow(ctx context.Context, operation string, sql string, args ...interface{}) pgx.Row {
	start := time.Now()

	// Choose the appropriate pool
	pool := db.GetReadPoolWithContext(ctx)
	row := pool.QueryRow(ctx, sql, args...)

	role := "read"
	if pool == db.WritePool {
		role = "write"
	}
	// Record the duration
	metrics.DBQueryDuration.WithLabelValues(operation, role).Observe(time.Since(start).Seconds())
	// Record query count
	metrics.DBQueriesTotal.WithLabelValues(operation, "success", role).Inc()

	return row
}

// TimedQuery wraps Query with duration metrics
func (db *Database) TimedQuery(ctx context.Context, operation string, sql string, args ...interface{}) (pgx.Rows, error) {
	start := time.Now()

	// Choose the appropriate pool
	pool := db.GetReadPoolWithContext(ctx)
	rows, err := pool.Query(ctx, sql, args...)

	role := "read"
	if pool == db.WritePool {
		role = "write"
	}
	// Record the duration
	metrics.DBQueryDuration.WithLabelValues(operation, role).Observe(time.Since(start).Seconds())
	// Record query count
	if err != nil {
		metrics.DBQueriesTotal.WithLabelValues(operation, "failure", role).Inc()
	} else {
		metrics.DBQueriesTotal.WithLabelValues(operation, "success", role).Inc()
	}

	return rows, err
}

// TimedExec wraps Exec with duration metrics
func (db *Database) TimedExec(ctx context.Context, operation string, sql string, args ...interface{}) error {
	start := time.Now()

	// Write operations always use write pool
	pool := db.GetWritePool()
	_, err := pool.Exec(ctx, sql, args...)

	// Record the duration
	metrics.DBQueryDuration.WithLabelValues(operation, "write").Observe(time.Since(start).Seconds())
	// Record query count
	if err != nil {
		metrics.DBQueriesTotal.WithLabelValues(operation, "failure", "write").Inc()
	} else {
		metrics.DBQueriesTotal.WithLabelValues(operation, "success", "write").Inc()
	}

	return err
}
