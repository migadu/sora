// Package cache provides a local filesystem cache for frequently accessed S3 objects.
//
// The cache reduces latency and S3 API calls by maintaining local copies of
// message bodies that are accessed frequently. It includes:
//   - SQLite-based metadata tracking
//   - LRU eviction based on size limits
//   - Metrics for hit/miss ratios
//   - Automatic warming for recently accessed mailboxes
//   - Content deduplication at read level
//
// # Cache Architecture
//
// The cache stores message bodies in a local directory structure with
// an SQLite database tracking metadata (access times, sizes, hashes).
// When a message is requested:
//
//  1. Check local cache (fast path)
//  2. On miss, fetch from S3
//  3. Store in cache for future access
//  4. Track metrics for monitoring
//
// # Usage Example
//
//	// Initialize cache
//	cache, err := cache.NewCache(
//		"/var/cache/sora",
//		sourceDB,
//		10*1024*1024*1024, // 10 GB max size
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Get from cache (returns Reader)
//	reader, err := cache.Get(ctx, contentHash)
//	if err != nil {
//		// Not in cache, fetch from S3
//	}
//	defer reader.Close()
//
//	// Put into cache
//	err = cache.Put(ctx, contentHash, messageBody)
//
//	// Warm cache for a mailbox
//	err = cache.WarmCache(ctx, AccountID, []string{"INBOX"}, 100)
//
// # Metrics
//
// The cache tracks:
//   - Hit/miss ratios
//   - Total size
//   - Access patterns
//   - Eviction statistics
//
// Access metrics via:
//
//	stats := cache.Stats()
//	fmt.Printf("Hit ratio: %.2f%%\n", stats.HitRatio*100)
//
// # Cache Warming
//
// For better performance, warm the cache when a user logs in:
//
//	cache.WarmCache(ctx, AccountID, []string{"INBOX", "Sent"}, 50)
//
// This pre-loads the 50 most recent messages from specified mailboxes.
package cache

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	_ "modernc.org/sqlite"
)

// SourceDatabase defines the interface for interacting with the main database.
// This allows for mocking in tests.
type SourceDatabase interface {
	FindExistingContentHashesWithRetry(ctx context.Context, hashes []string) ([]string, error)
	GetRecentMessagesForWarmupWithRetry(ctx context.Context, AccountID int64, mailboxNames []string, messageCount int) (map[string][]string, error)
}

const DataDir = "data"
const IndexDB = "cache_index.db"
const PurgeBatchSize = 1000

// ErrObjectTooLarge is returned when attempting to cache an object that exceeds the size limit
var ErrObjectTooLarge = errors.New("object exceeds cache size limit")

type Cache struct {
	basePath         string
	capacity         int64
	maxObjectSize    int64
	purgeInterval    time.Duration
	orphanCleanupAge time.Duration
	db               *sql.DB
	mu               sync.Mutex
	sourceDB         SourceDatabase
	// Metrics - using atomic for thread-safe counters
	cacheHits   int64
	cacheMisses int64
	startTime   time.Time
}

// Close closes the cache database connection
func (c *Cache) Close() error {
	if c.db != nil {
		logger.Info("Cache: closing cache database connection")
		return c.db.Close()
	}
	return nil
}

func New(basePath string, maxSizeBytes int64, maxObjectSize int64, purgeInterval time.Duration, orphanCleanupAge time.Duration, sourceDb SourceDatabase) (*Cache, error) {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" {
		return nil, fmt.Errorf("cache base path cannot be empty")
	}
	basePath = filepath.Clean(basePath)
	dataDir := filepath.Join(basePath, DataDir)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache data path %s: %w", dataDir, err)
	}

	dbPath := filepath.Join(basePath, IndexDB)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache index DB: %w", err)
	}

	// Set busy timeout before enabling WAL to handle concurrent access
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
		logger.Warn("Cache: Failed to set busy_timeout", "error", err)
	}

	if _, err := db.Exec(`PRAGMA journal_mode = WAL;`); err != nil {
		// Log the warning, but allow to proceed as WAL is an optimization.
		logger.Warn("Cache: Failed to set PRAGMA journal_mode = WAL", "error", err)
	}

	// Verify WAL mode was actually set
	var journalMode string
	if err := db.QueryRow(`PRAGMA journal_mode;`).Scan(&journalMode); err != nil {
		logger.Warn("Cache: Failed to verify journal mode", "error", err)
	} else {
		logger.Info("Cache: SQLite journal mode", "mode", journalMode)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS cache_index (
		path TEXT PRIMARY KEY,
		size INTEGER NOT NULL,
		mod_time TIMESTAMP NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_cache_mod_time ON cache_index(mod_time);
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to create cache schema: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("cache DB ping failed: %w", err)
	}
	return &Cache{
		basePath:         basePath,
		capacity:         maxSizeBytes,
		maxObjectSize:    maxObjectSize,
		purgeInterval:    purgeInterval,
		orphanCleanupAge: orphanCleanupAge,
		db:               db,
		sourceDB:         sourceDb,
		startTime:        time.Now(),
	}, nil
}

func (c *Cache) Get(contentHash string) ([]byte, error) {
	path := c.GetPathForContentHash(contentHash)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			atomic.AddInt64(&c.cacheMisses, 1)
			metrics.CacheOperationsTotal.WithLabelValues("get", "miss").Inc()
		} else {
			metrics.CacheOperationsTotal.WithLabelValues("get", "error").Inc()
		}
		return nil, err
	}
	atomic.AddInt64(&c.cacheHits, 1)
	metrics.CacheOperationsTotal.WithLabelValues("get", "hit").Inc()
	return data, nil
}

func (c *Cache) Put(contentHash string, data []byte) error {
	if int64(len(data)) > c.maxObjectSize {
		metrics.CacheOperationsTotal.WithLabelValues("put", "rejected").Inc()
		return fmt.Errorf("%w: data size %d exceeds limit %d", ErrObjectTooLarge, len(data), c.maxObjectSize)
	}

	path := c.GetPathForContentHash(contentHash)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		metrics.CacheOperationsTotal.WithLabelValues("put", "error").Inc()
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Write to a temporary file first to minimize time holding the lock.
	// This also helps prevent corruption if the write is interrupted.
	tempFile, err := os.CreateTemp(dir, "put-*.tmp")
	if err != nil {
		metrics.CacheOperationsTotal.WithLabelValues("put", "error").Inc()
		return fmt.Errorf("failed to create temporary cache file: %w", err)
	}
	defer os.Remove(tempFile.Name()) // Ensure temp file is cleaned up on return

	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close() // Attempt to close, but prioritize write error
		metrics.CacheOperationsTotal.WithLabelValues("put", "error").Inc()
		return fmt.Errorf("failed to write to temporary cache file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		metrics.CacheOperationsTotal.WithLabelValues("put", "error").Inc()
		return fmt.Errorf("failed to close temporary cache file: %w", err)
	}

	// Atomically move the file into its final location.
	if err := os.Rename(tempFile.Name(), path); err != nil {
		// If rename fails because the file exists, it means another process cached it. This is not an error.
		if !os.IsExist(err) {
			metrics.CacheOperationsTotal.WithLabelValues("put", "error").Inc()
			return fmt.Errorf("failed to move temporary file to final cache location %s: %w", path, err)
		}
		logger.Info("Cache: File appeared during rename - assuming concurrent cache success", "path", path)
	}

	// Now, acquire lock just to update the index.
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.trackFile(path); err != nil {
		// The file exists, but we failed to track it. The next purge/sync cycle might fix it.
		// We don't remove the file here because it might be a valid cache entry from a concurrent Put.
		metrics.CacheOperationsTotal.WithLabelValues("put", "error").Inc()
		return fmt.Errorf("failed to track cache file %s: %w", path, err)
	}
	logger.Info("Cache: Cached file", "path", path)
	metrics.CacheOperationsTotal.WithLabelValues("put", "success").Inc()
	return nil
}

func (c *Cache) Exists(contentHash string) (bool, error) {
	path := c.GetPathForContentHash(contentHash)
	c.mu.Lock()
	defer c.mu.Unlock()

	var count int
	// Querying the index is more reliable than checking the filesystem (avoids TOCTOU races)
	// and is generally faster.
	err := c.db.QueryRow(`SELECT COUNT(*) FROM cache_index WHERE path = ?`, path).Scan(&count)
	if err != nil {
		// This is an internal DB error, not a cache miss.
		logger.Error("Cache: Failed to query index for existence", "path", path, "error", err)
		return false, fmt.Errorf("failed to query cache index: %w", err)
	}

	exists := count > 0
	if exists {
		atomic.AddInt64(&c.cacheHits, 1)
	} else {
		atomic.AddInt64(&c.cacheMisses, 1)
	}
	return exists, nil
}
func (c *Cache) Delete(contentHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := c.GetPathForContentHash(contentHash)
	if err := os.Remove(path); err != nil {
		// If the file doesn't exist, we can consider the delete successful for the cache's state.
		if !errors.Is(err, os.ErrNotExist) {
			logger.Error("Cache: Failed to remove cache file", "path", path, "error", err)
			return fmt.Errorf("failed to remove cache file %s: %w", path, err)
		}
	}
	// Always try to remove from index, even if file was already gone.
	if _, err := c.db.Exec(`DELETE FROM cache_index WHERE path = ?`, path); err != nil {
		// Log the error, as this means the index might be out of sync.
		logger.Error("Cache: Failed to remove index entry", "path", path, "error", err)
		return fmt.Errorf("failed to remove index entry for path %s: %w", path, err)
	}

	// Clean up empty parent directories.
	dataDir := filepath.Join(c.basePath, DataDir)
	removeEmptyParents(path, dataDir)
	return nil
}

func (c *Cache) MoveIn(path string, contentHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	target := c.GetPathForContentHash(contentHash)

	// Check if the file already exists. If so, our work is done.
	// We just need to remove the source file.
	if _, err := os.Stat(target); err == nil {
		logger.Info("Cache: File already exists in cache - removing source", "target", target, "source", path)
		if err := os.Remove(path); err != nil {
			// Log the error but don't fail the operation, as the file is in the cache.
			logger.Error("Cache: Failed to remove source file after finding existing cache entry", "path", path, "error", err)
		}
		// Ensure the file is tracked, in case it was present on disk but not in the index.
		return c.trackFile(target)
	}

	// File does not exist, so proceed with moving it.
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		logger.Error("Cache: Failed to create target directory", "dir", filepath.Dir(target), "error", err)
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	// Try rename first (fast path)
	if err := os.Rename(path, target); err != nil {
		// If rename fails, it's not because the file exists (we checked that).
		// It's likely a cross-device error.
		if isCrossDeviceError(err) {
			// Cross-device link error (common on Unix), fall back to copy+delete.
			logger.Info("Cache: Cross-device link detected - falling back to copy+delete", "source", path, "target", target)
			if err := copyFile(path, target); err != nil {
				logger.Error("Cache: Failed to copy file", "from", path, "to", target, "error", err)
				return fmt.Errorf("failed to copy file into cache: %w", err)
			}
			if err := os.Remove(path); err != nil {
				logger.Error("Cache: Failed to remove source file after copy", "path", path, "error", err)
				// File was copied successfully, so continue with tracking.
			}
		} else {
			// Another type of error occurred.
			logger.Error("Cache: Failed to move file", "from", path, "to", target, "error", err)
			return fmt.Errorf("failed to move file into cache: %w", err)
		}
	}

	if err := c.trackFile(target); err != nil {
		logger.Error("Cache: Failed to track file - file was moved but not tracked", "path", target, "error", err)
		// The file is already moved. If tracking fails, the cache is inconsistent.
		// This might be caught by RemoveStaleDBEntries if the file exists but isn't in DB,
		// or SyncFromDisk might re-track it.
		return fmt.Errorf("failed to track moved cache file %s: %w", target, err)
	}
	return nil
}

func (c *Cache) trackFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	_, err = c.db.Exec(`INSERT OR REPLACE INTO cache_index (path, size, mod_time) VALUES (?, ?, ?)`, path, info.Size(), info.ModTime())
	return err
}

func removeEmptyParents(path string, stopAt string) {
	for {
		dir := filepath.Dir(path)
		if dir == stopAt || dir == "." || dir == "/" {
			break
		}
		err := os.Remove(dir)
		if err != nil {
			// Not empty or permission denied, stop cleanup
			break
		}
		path = dir
	}
}

type fileStat struct {
	path    string
	size    int64
	modTime time.Time
}

func (c *Cache) SyncFromDisk() error {
	logger.Info("Cache: starting disk sync")
	var files []fileStat

	// Phase 1: Walk disk and collect file info (no lock)
	dataDir := filepath.Join(c.basePath, DataDir)
	err := filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			info, statErr := d.Info()
			if statErr != nil {
				logger.Error("Cache: Failed to get stat during sync", "path", path, "error", statErr)
				return nil // Continue walking
			}
			files = append(files, fileStat{path: path, size: info.Size(), modTime: info.ModTime()})
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk cache directory: %w", err)
	}
	if len(files) > 0 {
		logger.Info("Cache: Found files on disk - updating index", "count", len(files))
		// Phase 2: Update index in a single transaction (short lock)
		c.mu.Lock()
		tx, err := c.db.Begin()
		if err != nil {
			c.mu.Unlock()
			return fmt.Errorf("failed to begin transaction for disk sync: %w", err)
		}

		stmt, err := tx.Prepare(`INSERT OR REPLACE INTO cache_index (path, size, mod_time) VALUES (?, ?, ?)`)
		if err != nil {
			tx.Rollback()
			c.mu.Unlock()
			return fmt.Errorf("failed to prepare statement for disk sync: %w", err)
		}
		defer stmt.Close()

		for _, f := range files {
			if _, err := stmt.Exec(f.path, f.size, f.modTime); err != nil {
				logger.Error("Cache: Error tracking file during sync", "path", f.path, "error", err)
				// Continue, try to sync as much as possible
			}
		}

		if err := tx.Commit(); err != nil {
			c.mu.Unlock()
			return fmt.Errorf("failed to commit disk sync transaction: %w", err)
		}
		c.mu.Unlock()
		logger.Info("Cache: index update complete")
	}
	// Phase 3: Clean up stale entries and directories (uses its own locking)
	ctx := context.Background()
	if err := c.RemoveStaleDBEntries(ctx); err != nil {
		return fmt.Errorf("failed to remove stale DB entries after sync: %w", err)
	}
	return c.cleanupStaleDirectories()
}

func (c *Cache) StartPurgeLoop(ctx context.Context) {
	go func() {
		// Run immediately on startup
		c.runPurgeCycle(ctx)

		ticker := time.NewTicker(c.purgeInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.runPurgeCycle(ctx)
			}
		}
	}()
}

func (c *Cache) runPurgeCycle(ctx context.Context) {
	logger.Info("Cache: running cache purge cycle")
	if err := c.PurgeIfNeeded(ctx); err != nil {
		logger.Warn("Cache: Purge failed", "error", err)
	}
	if err := c.RemoveStaleDBEntries(ctx); err != nil {
		logger.Error("Cache: Stale file cleanup error", "error", err)
	}
	if err := c.PurgeOrphanedContentHashes(ctx); err != nil {
		logger.Error("Cache: Orphan cleanup error", "error", err)
	}
}

func (c *Cache) cleanupStaleDirectories() error {
	dataDir := filepath.Join(c.basePath, DataDir)
	return filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// If WalkDir itself encounters an error trying to read a directory or stat an entry
			// (e.g., it disappeared between listing and stat-ing), err will be non-nil.
			// We want to log this but continue the walk if it's an ErrNotExist for the current path.
			var pathError *fs.PathError
			if errors.As(err, &pathError) && errors.Is(pathError.Err, os.ErrNotExist) && pathError.Path == path {
				logger.Info("Cache: Path no longer exists - skipping", "path", path, "error", err)
				return nil // Treat as skippable for this specific entry and continue walk
			}
			// For other errors encountered by WalkDir, propagate them to stop the walk.
			logger.Error("Cache: Error walking path", "path", path, "error", err)
			return err // Propagate other errors
		}
		if !d.IsDir() || path == dataDir {
			return nil
		}

		// Try to remove the directory — only works if it's empty
		removeErr := os.Remove(path)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && !isDirNotEmptyError(removeErr) {
			// Log unexpected errors during removal, but don't stop the walk.
			logger.Warn("Cache: Unexpected error removing directory", "path", path, "error", removeErr)
		}
		return nil
	})
}

// PurgeIfNeeded checks if the cache size exceeds its capacity and, if so,
// removes the least recently used items until it's within limits.
// This version is optimized to reduce lock contention and use batch database operations.
func (c *Cache) PurgeIfNeeded(ctx context.Context) error {
	// Phase 1: Check size and get candidates for deletion (read-only, minimal lock).
	pathsToPurge, err := c.getPurgeCandidates(ctx)
	if err != nil {
		return fmt.Errorf("failed to get purge candidates: %w", err)
	}
	if len(pathsToPurge) == 0 {
		return nil // Nothing to do.
	}

	// Phase 2: Delete files from the filesystem (slow, no lock needed).
	successfullyRemovedPaths := c.deleteFiles(pathsToPurge)

	if len(successfullyRemovedPaths) == 0 {
		logger.Info("Cache: attempted to purge files, but none were successfully removed from filesystem")
		return nil
	}

	// Phase 3: Remove entries from the database index in a single batch (write, short lock).
	if err := c.removeIndexEntries(ctx, successfullyRemovedPaths); err != nil {
		return fmt.Errorf("failed to remove purged files from index: %w", err)
	}

	// Optional: Cleanup empty parent directories.
	dataDir := filepath.Join(c.basePath, DataDir)
	for _, path := range successfullyRemovedPaths {
		removeEmptyParents(path, dataDir)
	}

	// Final cleanup of any other empty dirs that might have been left.
	if err := c.cleanupStaleDirectories(); err != nil {
		logger.Error("Cache: Error during post-purge directory cleanup", "error", err)
	}

	return nil
}

// getPurgeCandidates identifies which files to purge to get back under capacity.
// It holds a lock only for the duration of the database query.
func (c *Cache) getPurgeCandidates(ctx context.Context) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var totalSize int64
	row := c.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(size), 0) FROM cache_index`)
	if err := row.Scan(&totalSize); err != nil {
		return nil, fmt.Errorf("failed to get total cache size: %w", err)
	}

	if totalSize <= c.capacity {
		return nil, nil // Cache is within capacity, nothing to do.
	}

	logger.Info("Cache: Size exceeds capacity - identifying files to purge", "size", totalSize, "capacity", c.capacity)
	amountToFree := totalSize - c.capacity

	// Query for the oldest files sufficient to free up the required space.
	rows, err := c.db.QueryContext(ctx, `SELECT path, size FROM cache_index ORDER BY mod_time ASC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query for purge candidates: %w", err)
	}
	defer rows.Close()

	var pathsToPurge []string
	var freedSoFar int64
	for rows.Next() {
		var path string
		var size int64
		if err := rows.Scan(&path, &size); err != nil {
			logger.Error("Cache: Error scanning purge candidate", "error", err)
			continue
		}
		pathsToPurge = append(pathsToPurge, path)
		freedSoFar += size
		if freedSoFar >= amountToFree {
			break // We have enough candidates.
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating purge candidates: %w", err)
	}

	logger.Info("Cache: Identified files to purge", "count", len(pathsToPurge), "bytes_to_free", amountToFree)
	return pathsToPurge, nil
}

// deleteFiles removes files from the filesystem and returns a slice of paths that were successfully removed.
func (c *Cache) deleteFiles(paths []string) []string {
	var successfullyRemoved []string
	for _, path := range paths {
		// os.Remove is idempotent on non-existent files if we check the error.
		if err := os.Remove(path); err == nil || os.IsNotExist(err) {
			successfullyRemoved = append(successfullyRemoved, path)
		} else {
			logger.Error("Cache: Failed to remove file during purge", "path", path, "error", err)
		}
	}
	return successfullyRemoved
}

// removeIndexEntries removes a batch of paths from the cache index.
func (c *Cache) removeIndexEntries(ctx context.Context, paths []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for index removal: %w", err)
	}
	defer tx.Rollback()

	// For SQLite, we build a query with placeholders for batch delete.
	// This is safe as paths are generated internally.
	if len(paths) == 0 {
		return nil
	}
	query := `DELETE FROM cache_index WHERE path IN (?` + strings.Repeat(",?", len(paths)-1) + `)`
	args := make([]any, len(paths))
	for i, p := range paths {
		args[i] = p
	}

	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to batch delete from index: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit index deletions: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	logger.Info("Cache: Removed entries from index", "count", rowsAffected)
	return nil
}

func (c *Cache) PurgeOrphanedContentHashes(ctx context.Context) error {
	// This function runs without a lock initially to read from the DB.
	// The lock is acquired per-batch inside purgeHashBatch during the write phase.
	// This is safe because we are using WAL mode for SQLite, which allows concurrent reads and writes.
	threshold := time.Now().Add(-c.orphanCleanupAge)
	rows, err := c.db.Query(`SELECT path FROM cache_index WHERE mod_time < ?`, threshold)
	if err != nil {
		return err
	}
	defer rows.Close()

	var batch []string // Stores contentHashes
	var paths []string
	purged := 0

	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			logger.Error("Cache: Error scanning path", "error", err)
			continue
		}

		// Reconstruct the content hash from the file path.
		// The path is like /.../data_dir/ab/cd/ef...
		// We need to get the path relative to data_dir and remove separators.
		dataDir := filepath.Join(c.basePath, DataDir)
		relPath, err := filepath.Rel(dataDir, path)
		if err != nil {
			logger.Error("Cache: Could not determine relative path", "path", path, "error", err)
			continue
		}
		contentHash := strings.ReplaceAll(relPath, string(filepath.Separator), "")
		if len(contentHash) == 0 {
			continue
		}

		batch = append(batch, contentHash)
		paths = append(paths, path)

		if len(batch) >= PurgeBatchSize {
			purged += c.purgeHashBatch(ctx, batch, paths)
			batch = make([]string, 0, PurgeBatchSize)
			paths = make([]string, 0, PurgeBatchSize)
		}
	}

	if len(batch) > 0 {
		purged += c.purgeHashBatch(ctx, batch, paths)
	}

	if purged > 0 {
		logger.Info("Cache: Removed orphaned entries", "count", purged)
	}

	return nil
}

func (c *Cache) purgeHashBatch(ctx context.Context, contentHashes []string, paths []string) int {
	// Phase 1: Check against the main database (slow network call, no lock needed).
	existingDBHashes, err := c.sourceDB.FindExistingContentHashesWithRetry(ctx, contentHashes)
	if err != nil {
		logger.Error("Cache: Error finding existing content hashes from sourceDB", "error", err)
		return 0
	}

	existsMap := make(map[string]bool)
	for _, hash := range existingDBHashes {
		existsMap[hash] = true
	}

	// Phase 2: Identify which files are true orphans and can be deleted.
	var pathsToDelete []string
	for i, currentHash := range contentHashes {
		if !existsMap[currentHash] {
			pathsToDelete = append(pathsToDelete, paths[i])
		}
	}

	if len(pathsToDelete) == 0 {
		return 0
	}

	// Phase 3: Perform local filesystem and DB modifications under a lock.
	c.mu.Lock()
	defer c.mu.Unlock()

	dataDir := filepath.Join(c.basePath, DataDir)
	var successfullyRemovedPaths []string

	// Delete files from filesystem first.
	for _, path := range pathsToDelete {
		if err := os.Remove(path); err == nil || os.IsNotExist(err) {
			successfullyRemovedPaths = append(successfullyRemovedPaths, path)
			if err == nil {
				removeEmptyParents(path, dataDir)
			}
		} else {
			logger.Error("Cache: Error removing cached file", "path", path, "error", err)
		}
	}

	if len(successfullyRemovedPaths) == 0 {
		return 0
	}

	// Batch delete from the SQLite index inside a transaction.
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		logger.Error("Cache: Error beginning transaction", "error", err)
		return 0
	}
	defer tx.Rollback() // Rollback if not committed

	// SQLite doesn't support array parameters, so we build a query with placeholders.
	// This is safe as paths are generated internally, not from user input.
	query := `DELETE FROM cache_index WHERE path IN (?` + strings.Repeat(",?", len(successfullyRemovedPaths)-1) + `)`
	args := make([]any, len(successfullyRemovedPaths))
	for i, p := range successfullyRemovedPaths {
		args[i] = p
	}

	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		logger.Error("Cache: Error batch deleting from index", "error", err)
		return 0
	}

	if err := tx.Commit(); err != nil {
		logger.Error("Cache: Error committing transaction", "error", err)
		return 0
	}

	rowsAffected, _ := result.RowsAffected()
	return int(rowsAffected)
}

func (c *Cache) RemoveStaleDBEntries(ctx context.Context) error {
	// Phase 1: Get all indexed paths without holding the main lock.
	// This is safe due to SQLite's WAL mode allowing concurrent reads.
	rows, err := c.db.QueryContext(ctx, `SELECT path FROM cache_index`)
	if err != nil {
		return fmt.Errorf("failed to query cache_index: %w", err)
	}
	defer rows.Close()

	var allPaths []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			logger.Error("Cache: Error scanning path during stale check", "error", err)
			continue
		}
		allPaths = append(allPaths, path)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating indexed paths: %w", err)
	}

	// Phase 2: Check which files are missing from the filesystem (slow I/O, no lock).
	var stalePaths []string
	for _, path := range allPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			stalePaths = append(stalePaths, path)
		}
	}

	if len(stalePaths) == 0 {
		return nil // Nothing to do.
	}

	// Phase 3: Remove stale entries from the index in batches (write, short lock).
	logger.Info("Cache: Removing stale entries from index", "total", len(stalePaths))

	c.mu.Lock()
	defer c.mu.Unlock()

	const batchSize = 500 // SQLite variable limit is typically 999, use 500 for safety
	totalRemoved := int64(0)

	for i := 0; i < len(stalePaths); i += batchSize {
		end := i + batchSize
		if end > len(stalePaths) {
			end = len(stalePaths)
		}
		batch := stalePaths[i:end]

		tx, err := c.db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("failed to begin transaction for stale entry removal (batch %d): %w", i/batchSize, err)
		}

		query := `DELETE FROM cache_index WHERE path IN (?` + strings.Repeat(",?", len(batch)-1) + `)`
		args := make([]any, len(batch))
		for j, p := range batch {
			args[j] = p
		}

		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("failed to batch delete stale entries from index (batch %d): %w", i/batchSize, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit stale entry deletions (batch %d): %w", i/batchSize, err)
		}

		if rowsAffected, _ := result.RowsAffected(); rowsAffected > 0 {
			totalRemoved += rowsAffected
		}
	}

	logger.Info("Cache: Removed stale entries from index", "count", totalRemoved)
	return nil
}

// Get path for a given content hash, by splitting the hash into 3 parts
func (c *Cache) GetPathForContentHash(contentHash string) string {
	// Require a minimum length for the hash to be splittable as intended.
	if len(contentHash) < 4 { // Adjusted minimum length
		logger.Warn("Cache: Received short contentHash - using directly in data_dir path", "hash", contentHash)
		return filepath.Join(c.basePath, DataDir, contentHash) // Or return an error
	}
	return filepath.Join(c.basePath, DataDir, contentHash[:2], contentHash[2:4], contentHash[4:])
}

// isDirNotEmptyError checks if an error is due to a directory not being empty.
// This is OS-dependent.
func isDirNotEmptyError(err error) bool {
	// syscall.ENOTEMPTY is common on POSIX systems.
	return errors.Is(err, syscall.ENOTEMPTY)
}

// isCrossDeviceError checks if an error is due to a cross-device link.
func isCrossDeviceError(err error) bool {
	return errors.Is(err, syscall.EXDEV)
}

// copyFile copies a file from src to dst, preserving permissions.
// It performs an atomic write by first copying to a temporary file in the
// same directory and then renaming it to the final destination. This prevents
// readers from accessing a partially written file.
func copyFile(src, dst string) error {
	// Open the source file for reading.
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", src, err)
	}
	defer srcFile.Close()

	// Get source file info to preserve permissions.
	_, err = srcFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat source file %s: %w", src, err)
	}

	// Create a temporary file in the same directory as the destination.
	// This is crucial for an atomic os.Rename later.
	dstDir := filepath.Dir(dst)
	tempFile, err := os.CreateTemp(dstDir, "copy-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary file in %s: %w", dstDir, err)

	}
	// Ensure the temporary file is cleaned up if any error occurs before the final rename.
	defer os.Remove(tempFile.Name())

	// Copy the contents from source to the temporary file.
	if _, err = io.Copy(tempFile, srcFile); err != nil {
		tempFile.Close() // Attempt to close before removing.
		return fmt.Errorf("failed to copy data from %s to %s: %w", src, tempFile.Name(), err)
	}

	// Close the temporary file to ensure all data is flushed to disk.
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file %s: %w", tempFile.Name(), err)
	}

	// Atomically move the temporary file to its final destination.
	// This overwrites the destination if it exists, which is the desired behavior
	// in case of a race condition where another process cached the file.
	return os.Rename(tempFile.Name(), dst)
}

// CacheStats holds cache statistics
type CacheStats struct {
	ObjectCount int64
	TotalSize   int64
}

// CacheMetrics holds cache hit/miss metrics
type CacheMetrics struct {
	Hits       int64     `json:"hits"`
	Misses     int64     `json:"misses"`
	HitRate    float64   `json:"hit_rate"`
	TotalOps   int64     `json:"total_ops"`
	StartTime  time.Time `json:"start_time"`
	Uptime     string    `json:"uptime"`
	InstanceID string    `json:"instance_id"`
}

// GetStats returns current cache statistics
func (c *Cache) GetStats() (*CacheStats, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var objectCount int64
	var totalSize int64

	row := c.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size), 0) FROM cache_index`)
	if err := row.Scan(&objectCount, &totalSize); err != nil {
		return nil, fmt.Errorf("failed to query cache statistics: %w", err)
	}

	// Update Prometheus metrics
	metrics.CacheObjectsTotal.Set(float64(objectCount))
	metrics.CacheSizeBytes.Set(float64(totalSize))

	return &CacheStats{
		ObjectCount: objectCount,
		TotalSize:   totalSize,
	}, nil
}

// GetMetrics returns current cache hit/miss metrics
func (c *Cache) GetMetrics(instanceID string) *CacheMetrics {
	hits := atomic.LoadInt64(&c.cacheHits)
	misses := atomic.LoadInt64(&c.cacheMisses)
	totalOps := hits + misses

	var hitRate float64
	if totalOps > 0 {
		hitRate = float64(hits) / float64(totalOps) * 100
	}

	uptime := time.Since(c.startTime)

	return &CacheMetrics{
		Hits:       hits,
		Misses:     misses,
		HitRate:    hitRate,
		TotalOps:   totalOps,
		StartTime:  c.startTime,
		Uptime:     uptime.String(),
		InstanceID: instanceID,
	}
}

// ResetMetrics resets the hit/miss counters (useful for testing or periodic resets)
func (c *Cache) ResetMetrics() {
	atomic.StoreInt64(&c.cacheHits, 0)
	atomic.StoreInt64(&c.cacheMisses, 0)
	c.startTime = time.Now()
}

// PurgeAll removes all cached objects and clears the cache index
func (c *Cache) PurgeAll(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	logger.Info("Cache: purging all cached objects and clearing index")

	// Atomically and efficiently remove the entire data directory.
	dataDir := filepath.Join(c.basePath, DataDir)
	if err := os.RemoveAll(dataDir); err != nil {
		// If removal fails, we should not proceed to clear the index.
		return fmt.Errorf("failed to remove cache data directory %s: %w", dataDir, err)
	}

	// Recreate the data directory for future use.
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return fmt.Errorf("failed to recreate cache data directory %s: %w", dataDir, err)
	}

	// Clear the cache index in a single operation.
	if _, err := c.db.ExecContext(ctx, `DELETE FROM cache_index`); err != nil {
		return fmt.Errorf("failed to clear cache index: %w", err)
	}

	logger.Info("Cache: purge complete")
	return nil
}

// GetRecentMessagesForWarmup is a helper method that delegates to the source database
// This provides a convenient way for higher-level services to get warmup data through the cache
func (c *Cache) GetRecentMessagesForWarmup(ctx context.Context, AccountID int64, mailboxNames []string, messageCount int) (map[string][]string, error) {
	return c.sourceDB.GetRecentMessagesForWarmupWithRetry(ctx, AccountID, mailboxNames, messageCount)
}
