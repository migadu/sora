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
//   - A password change, a removed credential or a deleted account drops the account's
//     entries on every node within seconds (credchanges.Watcher reads credential_changes),
//     and at once through cluster gossip where the change came from the Admin API
//   - A login with another password than the cached one drops the entry and asks the database
//   - Unused entries are purged after a configurable period (default: 30 days)
package authcache

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/sqlitefile"
	_ "modernc.org/sqlite"
)

var (
	// ErrCacheMiss indicates the requested entry was not found in cache.
	ErrCacheMiss = errors.New("auth cache miss")

	// errNotAFile refuses an in-memory or temporary database. It is not corruption:
	// deleting the files named after the path and opening it again cannot help.
	errNotAFile = errors.New("an in-memory or temporary database does not persist")
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

	// A generation fences every credential lookup that began before an
	// invalidation. Mutations hold mu then stateMu; WAL readers only inspect
	// stateMu. One global counter keeps this independent of account count.
	stateMu    sync.RWMutex // state reads do not wait for last_used bookkeeping
	generation uint64
	suspended  bool
	unhealthy  bool // a failed revocation DELETE requires a full flush to recover

	// Tracks pending async goroutines (e.g., last_used updates). They
	// register under closeMu and only until closed is set, so that none
	// starts once Close has begun (see goAsync).
	closeMu sync.Mutex
	closed  bool
	wg      sync.WaitGroup
}

// New creates a new authentication cache backed by a SQLite database at dbPath, a file
// path or a file: URI (sqlitefile.Parse).
// If the existing database is corrupted, it is deleted and recreated only when
// the URI mode permits creating files (the default or mode=rwc).
// The cache is strictly optional — callers should handle errors gracefully and
// continue without caching rather than crashing.
func New(dbPath string, maxAge, purgeUnused, cleanupInterval time.Duration) (*Cache, error) {
	file, query, err := sqlitefile.Parse(dbPath)
	if err == nil && file == "" {
		err = fmt.Errorf("%q is not a file: %w", dbPath, errNotAFile)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open auth cache db: %w", err)
	}
	sqliteDB, err := openAndValidate(file, query)
	if err != nil {
		if !isCorruptionError(err) {
			// Not corruption (e.g. permission denied, missing directory,
			// read-only filesystem). Deleting and recreating cannot fix these
			// and would only produce a misleading "corrupted" log — surface the
			// real error so the operator can fix the path/permissions.
			return nil, fmt.Errorf("failed to open auth cache db: %w", err)
		}
		if create, _ := sqlitefile.CanCreate(query); !create {
			return nil, fmt.Errorf("cannot recreate corrupt auth cache with a no-create URI mode: %w", err)
		}
		// Database is genuinely corrupted — delete and recreate.
		logger.Warn("AuthCache: Database appears corrupted, recreating", "path", dbPath, "error", err)
		if removeErr := removeDBFiles(file); removeErr != nil {
			return nil, fmt.Errorf("failed to remove corrupted auth cache db: %w", removeErr)
		}
		sqliteDB, err = openAndValidate(file, query)
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

// isCorruptionError reports whether err indicates an actually corrupt SQLite
// database, as opposed to a filesystem or permission problem. Only corruption
// is safely recoverable by deleting and recreating the file; permission, path,
// and read-only errors must be surfaced so an operator can fix them rather than
// being silently (and futilely) "recreated".
func isCorruptionError(err error) bool {
	// Filesystem/access problems, and a database that is not a file, are never corruption.
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, fs.ErrNotExist) || errors.Is(err, errNotAFile) {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, sig := range []string{
		"disk image is malformed", // "database disk image is malformed"
		"malformed",
		"not a database", // "file is not a database"
		"file is encrypted",
	} {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

// connParams are the settings of each SQLite connection: a locked database is waited for
// up to 5 seconds, and commits sync at NORMAL, which WAL mode is safe from corruption
// with. They go in the DSN, which the driver applies to every connection the *sql.DB pool
// opens; a PRAGMA run with Exec on the pool sets them on one pooled connection only.
const connParams = "_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"

// openAndValidate opens the SQLite database file at path, 0600, with the URI query
// params (empty for none), sets pragmas, creates the schema, and runs an integrity
// check. Returns an error if any step fails.
func openAndValidate(path, params string) (*sql.DB, error) {
	if err := sqlitefile.Prepare(path, params); err != nil {
		return nil, err
	}
	// Open that same file: a plain path would be cut at its first '?'.
	if params != "" {
		params += "&"
	}
	dsn, err := sqlitefile.DSN(path, params+connParams)
	if err != nil {
		return nil, err
	}

	sqliteDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open: %w", err)
	}

	// The cache must be a database file. An in-memory or temporary database (":memory:",
	// "file::memory:", mode=memory, vfs=memdb, an empty name), for which SQLite reports
	// no file name, is private to the connection that opened it, or with a shared cache
	// lasts only while a connection is open: the pool's other connections would have no
	// schema and no rows, and none of it survives the restart the cache exists for. New
	// refuses the names known to open one before creating anything; this catches the rest.
	var file string
	if err := sqliteDB.QueryRow(`SELECT file FROM pragma_database_list WHERE name = 'main'`).Scan(&file); err != nil {
		sqliteDB.Close()
		return nil, fmt.Errorf("failed to read database file name: %w", err)
	}
	if file == "" {
		sqliteDB.Close()
		return nil, fmt.Errorf("%q is not a file: %w", path, errNotAFile)
	}

	// Set pragmas for performance
	if _, err := sqliteDB.Exec(`PRAGMA journal_mode = WAL`); err != nil {
		sqliteDB.Close()
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
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
	c.stateMu.RLock()
	generation := c.generation
	disabled := c.suspended || c.unhealthy
	c.stateMu.RUnlock()
	if disabled {
		c.misses.Add(1)
		metrics.AuthCacheOperations.WithLabelValues("miss").Inc()
		return 0, "", ErrCacheMiss
	}

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
	// A WAL reader may have observed the old row while an invalidation deleted
	// it. Do not let that snapshot escape after the invalidation completed.
	c.stateMu.RLock()
	invalidated := generation != c.generation || c.suspended || c.unhealthy
	c.stateMu.RUnlock()
	if invalidated {
		c.misses.Add(1)
		metrics.AuthCacheOperations.WithLabelValues("miss").Inc()
		return 0, "", ErrCacheMiss
	}

	// Update last_used and hit_count asynchronously (skipped once Close has
	// begun; the lookup still answers).
	now := time.Now().Unix()
	c.goAsync(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if _, err := c.db.Exec(`
			UPDATE auth_cache
			SET last_used = ?, hit_count = hit_count + 1
			WHERE address = ?
		`, now, address); err != nil {
			logger.Warn("AuthCache: Failed to update last_used", "address", address, "error", err)
		}
	})

	c.hits.Add(1)
	metrics.AuthCacheOperations.WithLabelValues("hit").Inc()
	return accountID, hashedPassword, nil
}

// MaxAge returns how old an entry may be and still be used.
func (c *Cache) MaxAge() time.Duration {
	return c.maxAge
}

// Generation returns the token to capture before reading credentials from the
// primary. PutIfGeneration discards the fill if an invalidation intervened.
func (c *Cache) Generation() uint64 {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.generation
}

// Suspend prevents persisted hits and new fills until the change feed has been
// synchronized. Authentication may still fall back to the primary database.
func (c *Cache) Suspend() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.generation++
	c.suspended = true
}

// EnsureRevocationNamespace binds persisted rows to this logical database and to
// the lossless credential-tracking implementation. It must run while suspended,
// before the initial change-feed replay. A cache from before tracking, or from
// another database, cannot prove that its passwords are still current. Flush it
// and record the new provenance atomically; matching warm restarts keep rows.
func (c *Cache) EnsureRevocationNamespace(ctx context.Context, databaseUUID string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	fail := func(err error) error {
		c.generation++
		c.unhealthy = true
		return fmt.Errorf("failed to establish auth cache revocation namespace: %w", err)
	}
	if !c.suspended {
		return fail(errors.New("cache must be suspended before namespace synchronization"))
	}
	identity, err := uuid.Parse(databaseUUID)
	if err != nil || identity == uuid.Nil {
		return fail(errors.New("database identity must be a nonzero UUID"))
	}
	databaseUUID = identity.String()
	const trackingVersion = 69
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS auth_cache_revocation (
		singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
		database_uuid TEXT NOT NULL, tracking_version INTEGER NOT NULL)`); err != nil {
		return fail(err)
	}
	var previousUUID string
	var previousVersion int
	err = tx.QueryRowContext(ctx, `SELECT database_uuid, tracking_version
		FROM auth_cache_revocation WHERE singleton = 1`).Scan(&previousUUID, &previousVersion)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fail(err)
	}
	changed := err != nil || previousUUID != databaseUUID || previousVersion != trackingVersion
	if changed {
		c.generation++
		if _, err := tx.ExecContext(ctx, `DELETE FROM auth_cache`); err != nil {
			return fail(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth_cache_revocation
			(singleton, database_uuid, tracking_version) VALUES (1, ?, ?)
			ON CONFLICT(singleton) DO UPDATE SET database_uuid=excluded.database_uuid,
			tracking_version=excluded.tracking_version`, databaseUUID, trackingVersion); err != nil {
			return fail(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fail(err)
	}
	if changed {
		c.unhealthy = false // the full flush and provenance change both committed
	}
	return nil
}

// Resume enables the cache after successful change-feed/sink synchronization.
// A failed invalidation may have left any account stale: deleting a different
// account successfully is insufficient, so recovery first flushes the cache.
func (c *Cache) Resume(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	wasDisabled := c.suspended || c.unhealthy
	if c.unhealthy {
		if _, err := c.db.ExecContext(ctx, `DELETE FROM auth_cache`); err != nil {
			return fmt.Errorf("failed to flush auth cache after invalidation failure: %w", err)
		}
		c.unhealthy = false
	}
	if wasDisabled {
		c.generation++
	}
	c.suspended = false
	return nil
}

// Put stores credentials in the cache, replacing any existing entry for the address.
func (c *Cache) Put(ctx context.Context, address string, accountID int64, hashedPassword string) error {
	return c.put(ctx, address, accountID, hashedPassword, nil)
}

// PutIfGeneration stores a primary lookup only if no invalidation or suspension
// occurred since its token was captured. An obsolete or disabled fill is silently
// discarded: caching is optional and the authentication already has its answer.
func (c *Cache) PutIfGeneration(ctx context.Context, address string, accountID int64, hashedPassword string, generation uint64) error {
	return c.put(ctx, address, accountID, hashedPassword, &generation)
}

func (c *Cache) put(ctx context.Context, address string, accountID int64, hashedPassword string, generation *uint64) error {
	address = strings.ToLower(strings.TrimSpace(address))
	if address == "" {
		return errors.New("address cannot be empty")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.suspended || c.unhealthy || (generation != nil && *generation != c.generation) {
		return nil
	}

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
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.generation++

	_, err := c.db.ExecContext(ctx, `DELETE FROM auth_cache WHERE address = ?`, address)
	if err != nil {
		c.unhealthy = true
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
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.generation++

	result, err := c.db.ExecContext(ctx, `DELETE FROM auth_cache WHERE account_id = ?`, accountID)
	if err != nil {
		c.unhealthy = true
		return fmt.Errorf("failed to invalidate account cache: %w", err)
	}

	count, _ := result.RowsAffected()
	if count > 0 {
		logger.Info("AuthCache: Invalidated account cache", "account_id", accountID, "entries_removed", count)
	}
	return nil
}

// InvalidateAccounts removes every entry of the given accounts, in one statement: the
// credential-change poll hands over all the accounts changed in its window at once.
func (c *Cache) InvalidateAccounts(ctx context.Context, accountIDs []int64) error {
	if len(accountIDs) == 0 {
		return nil
	}
	ids, err := json.Marshal(accountIDs)
	if err != nil {
		return fmt.Errorf("failed to encode account ids: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.generation++

	result, err := c.db.ExecContext(ctx, `DELETE FROM auth_cache WHERE account_id IN (SELECT value FROM json_each(?))`, string(ids))
	if err != nil {
		c.unhealthy = true
		return fmt.Errorf("failed to invalidate accounts in cache: %w", err)
	}
	if count, _ := result.RowsAffected(); count > 0 {
		logger.Info("AuthCache: Invalidated changed accounts", "accounts", len(accountIDs), "entries_removed", count)
	}
	return nil
}

// InvalidateAll discards persisted credentials when a change-feed gap exceeds
// retained history. Suspend/Resume still control whether synchronized hits may
// be served; the full flush also repairs any earlier failed revocation DELETE.
func (c *Cache) InvalidateAll(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	c.generation++
	if _, err := c.db.ExecContext(ctx, `DELETE FROM auth_cache`); err != nil {
		c.unhealthy = true
		return fmt.Errorf("failed to invalidate all auth cache entries: %w", err)
	}
	c.unhealthy = false
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

// goAsync runs f in a new goroutine that Close waits for, or not at all once
// Close has begun. Registering under closeMu orders every wg.Add before
// Close's wg.Wait, as sync.WaitGroup requires, so no update can start after
// the wait and reach the closed database.
func (c *Cache) goAsync(f func()) {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		f()
	}()
}

// Close stops starting async operations, waits for the pending ones and
// closes the underlying SQLite database.
func (c *Cache) Close() error {
	c.closeMu.Lock()
	c.closed = true
	c.closeMu.Unlock()
	c.wg.Wait() // Wait for pending async goroutines (last_used updates)
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}
