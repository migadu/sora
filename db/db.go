// Package db provides PostgreSQL database operations for the Sora email server.
//
// This package implements the data access layer with support for:
//   - Connection pooling with read/write separation
//   - Automatic failover between database hosts
//   - Schema migrations using embedded SQL files
//   - Full-text search with PostgreSQL pg_trgm
//   - Background workers for cleanup and S3 uploads
//   - Comprehensive retry logic and resilience patterns
//
// # Database Schema
//
// The schema includes tables for accounts, credentials, mailboxes, messages,
// SIEVE scripts, vacation tracking, and authentication rate limiting.
// See db/migrations/*.sql for the complete schema definition.
//
// # Connection Management
//
// The package uses pgxpool for efficient connection pooling:
//
//	cfg := &config.DatabaseConfig{
//		Write: &config.DatabaseEndpointConfig{
//			Hosts: []string{"localhost"},
//			Port: 5432,
//			User: "postgres",
//			Password: "password",
//			Name: "sora_mail_db",
//		},
//	}
//	db, err := NewDatabaseFromConfig(ctx, cfg, true, false)
//
// # Message Operations
//
// Common operations include appending messages, fetching message data,
// searching with full-text indexes, and managing flags:
//
//	// Append a message
//	msg := &Message{
//		MailboxID:    mailboxID,
//		ContentHash:  hash,
//		Size:         len(body),
//		InternalDate: time.Now(),
//	}
//	uid, err := db.AppendMessage(ctx, msg)
//
//	// Search messages
//	results, err := db.SearchMessages(ctx, mailboxID, criteria)
//
// # Background Workers
//
// Two background workers run continuously:
//   - Cleaner: Permanently deletes expunged messages after grace period
//   - Upload Worker: Processes queued S3 uploads in batches
//
// Start workers with:
//
//	db.StartCleanupWorker(ctx, 5*time.Minute, 24*time.Hour)
//	db.StartUploadWorker(ctx, 100, 5*time.Second)
package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-migrate/migrate/v4"
	pgxv5 "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // For database/sql compatibility
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/metrics"
)

//go:embed migrations/*.sql
var MigrationsFS embed.FS

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
	lockConn      *pgxpool.Conn    // Connection holding the advisory lock
}

func (db *Database) Close() {
	// Release the advisory lock first, while the connection is still valid.
	if db.lockConn != nil {
		// We use a background context with a timeout because the main application
		// context might have been cancelled during shutdown.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var unlocked bool
		err := db.lockConn.QueryRow(ctx, "SELECT pg_advisory_unlock_shared($1)", consts.SoraAdvisoryLockID).Scan(&unlocked)
		if err != nil {
			// Check if this is a connection termination error (expected during shutdown)
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "57P01" {
				// 57P01 = admin_shutdown - connection terminated by administrator
				// This is expected during graceful shutdown, lock is auto-released
				log.Println("Database: advisory lock auto-released (connection terminated during shutdown).")
			} else {
				log.Printf("Database: failed to explicitly release advisory lock (lock may have been auto-released): %v", err)
			}
		} else if unlocked {
			log.Println("Database: released shared database advisory lock.")
		} else {
			log.Println("Database: advisory lock was not held at time of release (likely auto-released on connection close).")
		}
		db.lockConn.Release()
	}

	// Now, close the connection pools.
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

func (db *Database) migrate(ctx context.Context, migrationTimeout time.Duration) error {
	// FAST PATH: Check current database version BEFORE setting up migration infrastructure.
	// This avoids expensive migration driver initialization when migrations are already up-to-date.
	// This is critical during concurrent instance restarts to prevent contention on migration locks.

	var currentVersion uint
	var dirty bool

	// Query the schema_migrations table directly using the existing pool
	err := db.WritePool.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&currentVersion, &dirty)
	if err != nil && err != pgx.ErrNoRows {
		// If the table doesn't exist yet, we'll catch it below and run migrations
		log.Printf("Database: could not query schema_migrations table (may not exist yet): %v", err)
	} else if err == nil {
		// Table exists and we got a version
		if dirty {
			return fmt.Errorf("database is in a dirty migration state (version %d). Manual intervention required", currentVersion)
		}

		// Now check the latest available migration version from embedded files
		migrations, err := fs.Sub(MigrationsFS, "migrations")
		if err != nil {
			return fmt.Errorf("failed to get migrations subdirectory: %w", err)
		}

		sourceDriver, err := iofs.New(migrations, ".")
		if err != nil {
			return fmt.Errorf("failed to create migration source driver: %w", err)
		}

		firstVersion, err := sourceDriver.First()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				log.Printf("Database: no migration files found. Database is at version %d.", currentVersion)
				return nil
			}
			return fmt.Errorf("failed to get first migration version: %w", err)
		}

		// Find the latest migration version
		latestVersion := firstVersion
		currentSourceVersion := firstVersion
		for {
			next, err := sourceDriver.Next(currentSourceVersion)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					break
				}
				return fmt.Errorf("failed to iterate migration versions: %w", err)
			}
			latestVersion = next
			currentSourceVersion = next
		}

		// Fast exit if already up-to-date
		if currentVersion >= latestVersion {
			log.Printf("Database: migrations are up to date (database: %d, latest: %d). Skipping migration infrastructure setup.", currentVersion, latestVersion)
			return nil
		}

		log.Printf("Database: migrations needed (database: %d, latest: %d). Proceeding with migration...", currentVersion, latestVersion)
	}

	// SLOW PATH: Migrations are needed or schema_migrations doesn't exist yet.
	// Set up the full migration infrastructure and run migrations.

	migrations, err := fs.Sub(MigrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("failed to get migrations subdirectory: %w", err)
	}

	sourceDriver, err := iofs.New(migrations, ".")
	if err != nil {
		return fmt.Errorf("failed to create migration source driver: %w", err)
	}

	// Find the latest available migration version for verification later
	firstVersion, err := sourceDriver.First()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Println("Database: no migration files found. Skipping migrations.")
			return nil
		}
		return fmt.Errorf("failed to get first migration version: %w", err)
	}

	latestVersion := firstVersion
	currentSourceVersion := firstVersion
	for {
		next, err := sourceDriver.Next(currentSourceVersion)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				break
			}
			return fmt.Errorf("failed to iterate migration versions: %w", err)
		}
		latestVersion = next
		currentSourceVersion = next
	}

	// The pgx/v5 migrate driver's WithInstance function expects a *sql.DB instance.
	// We'll create a temporary one from our existing pool's configuration.
	sqlDB, err := sql.Open("pgx", db.WritePool.Config().ConnString())
	if err != nil {
		return fmt.Errorf("failed to open a temporary sql.DB for migrations: %w", err)
	}
	defer sqlDB.Close()

	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("failed to ping temporary DB for migrations: %w", err)
	}

	dbDriver, err := pgxv5.WithInstance(sqlDB, &pgxv5.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migration db driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "pgx5", dbDriver)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	m.Log = &migrationLogger{}

	// Get current version from migration driver (needed for proper state tracking)
	currentVersion, dirty, err = m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return fmt.Errorf("failed to get current migration version: %w", err)
	}
	if dirty {
		return fmt.Errorf("database is in a dirty migration state (version %d). Manual intervention required", currentVersion)
	}

	log.Printf("Database: current migration version: %d, running migrations...", currentVersion)

	// Run migrations with timeout context to prevent hanging forever
	// If another instance is running migrations, this will wait up to the configured timeout
	log.Printf("Database: migration timeout configured: %v", migrationTimeout)
	migrateCtx, cancel := context.WithTimeout(ctx, migrationTimeout)
	defer cancel()

	// Create a channel to run migrations asynchronously
	errChan := make(chan error, 1)
	go func() {
		log.Println("Database: attempting to run migrations...")
		errChan <- m.Up()
	}()

	// Wait for either completion or timeout
	select {
	case err := <-errChan:
		// Check if error is a lock acquisition timeout (another instance is running migrations)
		if err != nil && err != migrate.ErrNoChange {
			// If it's a lock acquisition error, verify migrations instead of failing
			if errors.Is(err, migrate.ErrLockTimeout) {
				log.Println("Database: migration lock acquisition failed (another instance is running migrations)")
				log.Println("Database: verifying current migration state...")

				// Query schema_migrations directly to avoid lock contention
				var newVersion uint
				var dirty bool
				queryErr := sqlDB.QueryRow("SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&newVersion, &dirty)
				if queryErr != nil && queryErr != sql.ErrNoRows {
					return fmt.Errorf("failed to verify migration version after lock timeout: %w", queryErr)
				}
				if dirty {
					return fmt.Errorf("database is in a dirty migration state after lock timeout (version %d)", newVersion)
				}

				// Check if the version is now up-to-date (>= latest available migration)
				if newVersion >= latestVersion {
					log.Printf("Database: migration version verified: %d (migrations completed by another instance)", newVersion)
				} else {
					return fmt.Errorf("lock acquisition failed and database is not up-to-date (current: %d, latest: %d)", newVersion, latestVersion)
				}
			} else {
				return fmt.Errorf("failed to run migrations: %w", err)
			}
		} else if err == migrate.ErrNoChange {
			log.Println("Database: migrations are up to date")
		} else {
			log.Println("Database: migrations applied successfully")
		}
	case <-migrateCtx.Done():
		// Timeout occurred - likely another instance is running migrations
		log.Println("Database: migration attempt timed out (another instance may be running migrations)")
		log.Println("Database: verifying current migration state...")

		// Query schema_migrations directly to avoid lock contention
		var newVersion uint
		var dirty bool
		queryErr := sqlDB.QueryRow("SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&newVersion, &dirty)
		if queryErr != nil && queryErr != sql.ErrNoRows {
			return fmt.Errorf("failed to verify migration version after timeout: %w", queryErr)
		}
		if dirty {
			return fmt.Errorf("database is in a dirty migration state after timeout (version %d)", newVersion)
		}

		// Check if the version is now up-to-date (>= latest available migration)
		if newVersion >= latestVersion {
			log.Printf("Database: migration version verified: %d (migrations completed by another instance)", newVersion)
		} else {
			return fmt.Errorf("timeout waiting for migrations and database is not up-to-date (current: %d, latest: %d)", newVersion, latestVersion)
		}
	}

	// Final verification
	version, dirty, err := m.Version()
	if err != nil && err != migrate.ErrNilVersion {
		return fmt.Errorf("failed to get final migration version: %w", err)
	}
	if dirty {
		return fmt.Errorf("database is in a dirty migration state (version %d). Manual intervention required", version)
	}

	log.Printf("Database: migration complete, current version: %d", version)
	return nil
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
		if maxConns > 0 && acquiredConns/maxConns > 0.90 {
			result["write"].IsHealthy = false
			log.Printf("[DB-HEALTH] Write pool unhealthy: high utilization (%.1f%%)", (acquiredConns/maxConns)*100)
		}
		if maxConns > 0 && constructingConns/maxConns > 0.20 {
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
		if maxConns > 0 && acquiredConns/maxConns > 0.90 {
			result["read"].IsHealthy = false
			log.Printf("[DB-HEALTH] Read pool unhealthy: high utilization (%.1f%%)", (acquiredConns/maxConns)*100)
		}
		if maxConns > 0 && constructingConns/maxConns > 0.20 {
			result["read"].IsHealthy = false
			log.Printf("[DB-HEALTH] Read pool unhealthy: too many constructing connections (%.1f%%)", (constructingConns/maxConns)*100)
		}
	}

	return result
}

// GetWriteFailoverStats returns failover statistics for write operations
func (db *Database) GetWriteFailoverStats() []map[string]any {
	if db.WriteFailover == nil {
		return nil
	}
	return db.WriteFailover.GetHostStats()
}

// GetReadFailoverStats returns failover statistics for read operations
func (db *Database) GetReadFailoverStats() []map[string]any {
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
	defer func() {
		_ = conn.Close(checkCtx) // Log or ignore error on close
	}()
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
func NewDatabaseFromConfig(ctx context.Context, dbConfig *config.DatabaseConfig, runMigrations bool, acquireLock bool) (*Database, error) {
	if dbConfig.Write == nil {
		return nil, fmt.Errorf("write database configuration is required")
	}

	// Determine the pool type for logging (allows resilient layer to override for read pools)
	poolType := "write"
	if dbConfig.PoolTypeOverride != "" {
		poolType = dbConfig.PoolTypeOverride
	}

	// Create write failover manager and pool
	writeFailover := NewFailoverManager(dbConfig.Write, poolType)
	writePool, err := createPoolFromEndpointWithFailover(ctx, dbConfig.Write, dbConfig.GetDebug(), poolType, writeFailover)
	if err != nil {
		return nil, fmt.Errorf("failed to create %s pool: %v", poolType, err)
	}

	// Create read pool and failover manager
	var readPool *pgxpool.Pool
	var readFailover *FailoverManager
	if dbConfig.Read != nil {
		readFailover = NewFailoverManager(dbConfig.Read, "read")
		readPool, err = createPoolFromEndpointWithFailover(ctx, dbConfig.Read, dbConfig.GetDebug(), "read", readFailover)
		if err != nil {
			// If all read replicas are down, fall back to write pool instead of failing startup
			log.Printf("Database: WARNING - failed to create read pool (all read replicas unreachable): %v", err)
			log.Printf("Database: falling back to write pool for read operations")
			readPool = writePool
			readFailover = writeFailover // Share the same failover manager
		}
	} else {
		// If no read config specified, use write pool for reads
		readPool = writePool
		readFailover = writeFailover // Share the same failover manager
	}

	db := &Database{
		WritePool:     writePool,
		ReadPool:      readPool,
		WriteFailover: writeFailover,
		ReadFailover:  readFailover,
	}

	if runMigrations {
		migrationTimeout, err := dbConfig.GetMigrationTimeout()
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("invalid migration_timeout: %w", err)
		}
		if err := db.migrate(ctx, migrationTimeout); err != nil {
			db.Close()
			return nil, err
		}
	}

	if acquireLock {
		// Acquire and hold an advisory lock to signal that the server is running.
		log.Printf("Database: attempting to acquire connection from pool for advisory lock (pool stats: total=%d idle=%d acquired=%d max=%d)...",
			db.WritePool.Stat().TotalConns(), db.WritePool.Stat().IdleConns(),
			db.WritePool.Stat().AcquiredConns(), db.WritePool.Stat().MaxConns())

		// Use a timeout context for connection acquisition to prevent infinite blocking
		// if the pool is exhausted or the database is under heavy load during startup
		acquireCtx, acquireCancel := context.WithTimeout(ctx, 30*time.Second)
		defer acquireCancel()

		lockConn, err := db.WritePool.Acquire(acquireCtx)
		if err != nil {
			db.Close()
			if errors.Is(err, context.DeadlineExceeded) {
				return nil, fmt.Errorf("timeout acquiring connection for advisory lock after 30s (pool may be exhausted or database overloaded): pool stats: total=%d idle=%d acquired=%d max=%d",
					db.WritePool.Stat().TotalConns(), db.WritePool.Stat().IdleConns(),
					db.WritePool.Stat().AcquiredConns(), db.WritePool.Stat().MaxConns())
			}
			return nil, fmt.Errorf("failed to acquire connection for advisory lock: %w", err)
		}
		log.Println("Database: connection acquired from pool for advisory lock attempt")

		// Use a shared advisory lock. This allows multiple sora instances to run concurrently.
		// IMPORTANT: pg_try_advisory_lock_shared() returns immediately - it does NOT block.
		// It returns false ONLY if an EXCLUSIVE lock is held (e.g., by sora-admin migrate).
		// Multiple instances can hold shared locks simultaneously without any conflict.
		var lockAcquired bool
		maxRetries := 30                     // More attempts in case of transient exclusive locks
		retryDelay := 100 * time.Millisecond // Start with shorter delay

		for attempt := 0; attempt < maxRetries; attempt++ {
			if attempt > 0 {
				// Add jitter to prevent thundering herd when multiple instances restart simultaneously
				jitter := time.Duration(attempt*10) * time.Millisecond
				actualDelay := retryDelay + jitter

				log.Printf("Database: retrying advisory lock acquisition (attempt %d/%d) after %v (previous attempt returned false - exclusive lock held)...", attempt+1, maxRetries, actualDelay)
				time.Sleep(actualDelay)

				// Slower exponential backoff for shared locks (1.5x instead of 2x)
				retryDelay = time.Duration(float64(retryDelay) * 1.5)
				if retryDelay > 2*time.Second {
					retryDelay = 2 * time.Second // Lower cap since shared locks don't conflict
				}
			}

			err = lockConn.QueryRow(ctx, "SELECT pg_try_advisory_lock_shared($1)", consts.SoraAdvisoryLockID).Scan(&lockAcquired)
			if err != nil {
				lockConn.Release()
				db.Close()
				return nil, fmt.Errorf("failed to execute advisory lock query: %w", err)
			}

			if lockAcquired {
				log.Printf("Database: acquired shared database advisory lock (ID: %d).", consts.SoraAdvisoryLockID)
				db.lockConn = lockConn // Store the *pgxpool.Conn
				break
			}

			// Lock not acquired means an exclusive lock is currently held
			log.Printf("Database: shared advisory lock not available (attempt %d/%d) - exclusive lock held by another process (possibly sora-admin migrate)", attempt+1, maxRetries)
		}

		if !lockAcquired {
			lockConn.Release()
			db.Close()
			return nil, fmt.Errorf("could not acquire shared database lock (ID: %d) after %d attempts. An exclusive lock is being held (possibly by sora-admin migrate or another admin tool)", consts.SoraAdvisoryLockID, maxRetries)
		}
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

		// Add connect_timeout to fail fast on unreachable hosts (5 seconds)
		// This prevents long waits when a database host is down
		connString := fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s&connect_timeout=5",
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
		if endpoint.MaxConnections > 0 {
			config.MaxConns = int32(endpoint.MaxConnections)
		}
		if endpoint.MinConnections > 0 {
			config.MinConns = int32(endpoint.MinConnections)
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

		// Configure health check period to detect dead connections quickly
		// This runs a background goroutine that checks idle connections periodically
		config.HealthCheckPeriod = 15 * time.Second

		// Note: We don't use BeforeAcquire for connection validation because:
		// 1. It adds latency to every query (blocking acquire)
		// 2. HealthCheckPeriod already proactively removes dead connections
		// 3. Query-level timeouts in the resilient layer handle connection failures
		// 4. Dead connections will be detected on first query and removed from pool

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
		log.Printf("Database: %s pool created successfully with failover - host: %s", poolType, actualHost)
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
func (fm *FailoverManager) GetHostStats() []map[string]any {
	stats := make([]map[string]any, len(fm.hosts))
	for i, h := range fm.hosts {
		h.mu.RLock()
		stats[i] = map[string]any{
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
func (db *Database) BeginTx(ctx context.Context, txOptions pgx.TxOptions) (pgx.Tx, error) {
	tx, err := db.GetWritePool().BeginTx(ctx, txOptions)
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

// migrationLogger implements migrate.Logger interface
type migrationLogger struct{}

func (l *migrationLogger) Printf(format string, v ...any) {
	// Prepend a prefix to all migration logs for clarity
	log.Printf("[DB-MIGRATE] "+format, v...)
}

func (l *migrationLogger) Verbose() bool {
	// Set to true to see verbose migration output
	return true
}

func (mtx *measuredTx) Rollback(ctx context.Context) error {
	err := mtx.Tx.Rollback(ctx)
	// We count a rollback attempt even if the rollback itself fails.
	metrics.DBTransactionsTotal.WithLabelValues("rollback").Inc()
	metrics.DBTransactionDuration.Observe(time.Since(mtx.start).Seconds())
	return err
}
