// Package authcache provides a persistent authentication cache using SQLite.
//
// The cache stores credential lookups (address → account_id, password_hash) on disk
// so that after a proxy restart, authentication requests can be served locally instead
// of hitting the PostgreSQL database. This eliminates the "thundering herd" problem
// where thousands of clients reconnect simultaneously after a restart.
//
// # Architecture
//
//	┌──────────────┐    cache hit     ┌─────────────┐
//	│  Proxy Auth  │ ───────────────► │  SQLite DB   │  ~0.1ms
//	│  Request     │                  │  (local disk)│
//	│              │    cache miss    └─────────────┘
//	│              │ ───────────────► ┌─────────────┐
//	│              │                  │  PostgreSQL  │  ~10-50ms
//	└──────────────┘                  │  (network)   │
//	                                  └─────────────┘
//
// # Cache Invalidation
//
//   - Entries expire after a configurable max age (default: 7 days)
//   - Password changes invalidate the entry on next failed verification
//   - Unused entries are purged after a configurable period (default: 30 days)
//   - Account-wide invalidation is supported for account deletion
package authcache

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	_ "modernc.org/sqlite"
)

var (
	// ErrCacheMiss indicates the requested entry was not found in cache.
	ErrCacheMiss = errors.New("auth cache miss")
)

// Cache provides persistent authentication cache using SQLite.
type Cache struct {
	db              *sql.DB
	maxAge          time.Duration
	purgeUnused     time.Duration
	cleanupInterval time.Duration

	// In-memory hit/miss counters (atomic for lock-free updates)
	hits   atomic.Int64
	misses atomic.Int64

	// Protects write operations to SQLite (reads are concurrent via WAL)
	mu sync.Mutex

	// Tracks pending async goroutines (e.g., last_used updates)
	wg sync.WaitGroup
}

// New creates a new authentication cache backed by a SQLite database at dbPath.
// If the existing database is corrupted, it is automatically deleted and recreated.
// The cache is strictly optional — callers should handle errors gracefully and
// continue without caching rather than crashing.
func New(dbPath string, maxAge, purgeUnused, cleanupInterval time.Duration) (*Cache, error) {
	sqliteDB, err := openAndValidate(dbPath)
	if err != nil {
		// Database may be corrupted — try to recreate
		logger.Warn("AuthCache: Database appears corrupted, recreating", "path", dbPath, "error", err)
		if removeErr := removeDBFiles(dbPath); removeErr != nil {
			return nil, fmt.Errorf("failed to remove corrupted auth cache db: %w", removeErr)
		}
		sqliteDB, err = openAndValidate(dbPath)
		if err != nil {
			return nil, fmt.Errorf("failed to recreate auth cache db: %w", err)
		}
		logger.Info("AuthCache: Successfully recreated database", "path", dbPath)
	}

	cache := &Cache{
		db:              sqliteDB,
		maxAge:          maxAge,
		purgeUnused:     purgeUnused,
		cleanupInterval: cleanupInterval,
	}

	return cache, nil
}

// openAndValidate opens a SQLite database, sets pragmas, creates the schema,
// and runs an integrity check. Returns an error if any step fails.
func openAndValidate(dbPath string) (*sql.DB, error) {
	if dbPath != ":memory:" && !strings.HasPrefix(dbPath, "file:") {
		// Ensure the database file has 0600 permissions.
		// If the file does not exist, pre-create it with 0600 permissions.
		f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return nil, fmt.Errorf("failed to create or set permissions on database file: %w", err)
		}
		f.Close()
		// If the file already exists, enforce 0600 permissions on it.
		if err := os.Chmod(dbPath, 0600); err != nil {
			return nil, fmt.Errorf("failed to enforce 0600 permissions on database file: %w", err)
		}
	}

	sqliteDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open: %w", err)
	}

	// Set pragmas for performance
	if _, err := sqliteDB.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		sqliteDB.Close()
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}
	if _, err := sqliteDB.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		sqliteDB.Close()
		return nil, fmt.Errorf("failed to set busy_timeout: %w", err)
	}
	if _, err := sqliteDB.Exec(`PRAGMA synchronous = NORMAL`); err != nil {
		sqliteDB.Close()
		return nil, fmt.Errorf("failed to set synchronous mode: %w", err)
	}

	// Create schema
	schema := `
	CREATE TABLE IF NOT EXISTS auth_cache (
		address TEXT PRIMARY KEY,
		account_id INTEGER NOT NULL,
		password_hash TEXT NOT NULL,
		cached_at INTEGER NOT NULL,
		last_used INTEGER NOT NULL,
		hit_count INTEGER DEFAULT 0
	);
	CREATE INDEX IF NOT EXISTS idx_auth_cache_last_used ON auth_cache(last_used);
	CREATE INDEX IF NOT EXISTS idx_auth_cache_account_id ON auth_cache(account_id);
	`
	if _, err := sqliteDB.Exec(schema); err != nil {
		sqliteDB.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	// Quick integrity check — a simple query to ensure the table is usable
	var count int64
	if err := sqliteDB.QueryRow(`SELECT COUNT(*) FROM auth_cache`).Scan(&count); err != nil {
		sqliteDB.Close()
		return nil, fmt.Errorf("integrity check failed: %w", err)
	}

	return sqliteDB, nil
}

// removeDBFiles removes the SQLite database file and its WAL/SHM journal files.
func removeDBFiles(dbPath string) error {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		p := dbPath + suffix
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove %s: %w", p, err)
		}
	}
	return nil
}

// Get retrieves cached credentials for the given address.
// Returns ErrCacheMiss if the entry is not found or has expired.
func (c *Cache) Get(ctx context.Context, address string) (accountID int64, hashedPassword string, err error) {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return 0, "", errors.New("address cannot be empty")
	}

	maxCachedAt := time.Now().Add(-c.maxAge).Unix()

	err = c.db.QueryRowContext(ctx, `
		SELECT account_id, password_hash
		FROM auth_cache
		WHERE address = ? AND cached_at >= ?
	`, address, maxCachedAt).Scan(&accountID, &hashedPassword)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.misses.Add(1)
			metrics.AuthCacheOperations.WithLabelValues("miss").Inc()
			return 0, "", ErrCacheMiss
		}
		metrics.AuthCacheOperations.WithLabelValues("error").Inc()
		return 0, "", fmt.Errorf("auth cache query error: %w", err)
	}

	// Update last_used and hit_count asynchronously
	now := time.Now().Unix()
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.mu.Lock()
		defer c.mu.Unlock()
		if _, err := c.db.Exec(`
			UPDATE auth_cache
			SET last_used = ?, hit_count = hit_count + 1
			WHERE address = ?
		`, now, address); err != nil {
			logger.Warn("AuthCache: Failed to update last_used", "address", address, "error", err)
		}
	}()

	c.hits.Add(1)
	metrics.AuthCacheOperations.WithLabelValues("hit").Inc()
	return accountID, hashedPassword, nil
}

// Put stores credentials in the cache, replacing any existing entry for the address.
func (c *Cache) Put(ctx context.Context, address string, accountID int64, hashedPassword string) error {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return errors.New("address cannot be empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().Unix()
	_, err := c.db.ExecContext(ctx, `
		INSERT INTO auth_cache (address, account_id, password_hash, cached_at, last_used, hit_count)
		VALUES (?, ?, ?, ?, ?, 0)
		ON CONFLICT(address) DO UPDATE SET
			account_id = excluded.account_id,
			password_hash = excluded.password_hash,
			cached_at = excluded.cached_at,
			last_used = excluded.last_used
	`, address, accountID, hashedPassword, now, now)

	if err != nil {
		return fmt.Errorf("failed to cache credentials: %w", err)
	}

	return nil
}

// Invalidate removes a specific address from the cache.
// This should be called when a password change is detected.
func (c *Cache) Invalidate(ctx context.Context, address string) error {
	address = strings.ToLower(strings.TrimSpace(address))

	c.mu.Lock()
	defer c.mu.Unlock()

	_, err := c.db.ExecContext(ctx, `DELETE FROM auth_cache WHERE address = ?`, address)
	if err != nil {
		return fmt.Errorf("failed to invalidate cache entry: %w", err)
	}

	logger.Debug("AuthCache: Invalidated cache entry", "address", address)
	return nil
}

// InvalidateAccount removes all entries for an account.
// This should be called on account deletion.
func (c *Cache) InvalidateAccount(ctx context.Context, accountID int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	result, err := c.db.ExecContext(ctx, `DELETE FROM auth_cache WHERE account_id = ?`, accountID)
	if err != nil {
		return fmt.Errorf("failed to invalidate account cache: %w", err)
	}

	count, _ := result.RowsAffected()
	if count > 0 {
		logger.Info("AuthCache: Invalidated account cache", "account_id", accountID, "entries_removed", count)
	}
	return nil
}

// StartCleanupLoop runs periodic cleanup in a background goroutine.
// It removes expired and unused entries. The loop stops when ctx is cancelled.
func (c *Cache) StartCleanupLoop(ctx context.Context) {
	go func() {
		// Run immediately on startup
		c.cleanup(ctx)

		ticker := time.NewTicker(c.cleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.cleanup(ctx)
			}
		}
	}()
}

// cleanup removes old and unused entries.
func (c *Cache) cleanup(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Remove entries older than max_age
	maxAgeThreshold := now.Add(-c.maxAge).Unix()
	result1, err := c.db.ExecContext(ctx, `DELETE FROM auth_cache WHERE cached_at < ?`, maxAgeThreshold)
	if err != nil {
		logger.Error("AuthCache: Failed to purge old entries", "error", err)
	} else if count, _ := result1.RowsAffected(); count > 0 {
		logger.Info("AuthCache: Purged expired entries", "count", count, "max_age", c.maxAge)
	}

	// Remove entries unused for longer than purge_unused
	purgeUnusedThreshold := now.Add(-c.purgeUnused).Unix()
	result2, err := c.db.ExecContext(ctx, `DELETE FROM auth_cache WHERE last_used < ?`, purgeUnusedThreshold)
	if err != nil {
		logger.Error("AuthCache: Failed to purge unused entries", "error", err)
	} else if count, _ := result2.RowsAffected(); count > 0 {
		logger.Info("AuthCache: Purged unused entries", "count", count, "unused_for", c.purgeUnused)
	}

	// Update the entries gauge metric
	var totalEntries int64
	if err := c.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_cache`).Scan(&totalEntries); err == nil {
		metrics.AuthCacheEntries.Set(float64(totalEntries))
	}
}

// Stats returns cache statistics.
func (c *Cache) Stats(ctx context.Context) (totalEntries, lifetimeHits int64, hits, misses int64, hitRate float64, err error) {
	err = c.db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(hit_count), 0)
		FROM auth_cache
	`).Scan(&totalEntries, &lifetimeHits)
	if err != nil {
		return
	}

	hits = c.hits.Load()
	misses = c.misses.Load()
	totalOps := hits + misses
	if totalOps > 0 {
		hitRate = float64(hits) / float64(totalOps) * 100
	}

	return
}

// Close waits for pending async operations and closes the underlying SQLite database.
func (c *Cache) Close() error {
	c.wg.Wait() // Wait for pending async goroutines (last_used updates)
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}
