package cache

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/migadu/sora/pkg/resilient"
	_ "modernc.org/sqlite"
)

const DataDir = "data"
const IndexDB = "cache_index.db"
const PurgeBatchSize = 1000

type Cache struct {
	basePath         string
	capacity         int64
	maxObjectSize    int64
	purgeInterval    time.Duration
	orphanCleanupAge time.Duration
	db               *sql.DB
	mu               sync.Mutex
	sourceDB         *resilient.ResilientDatabase
	// Metrics - using atomic for thread-safe counters
	cacheHits   int64
	cacheMisses int64
	startTime   time.Time
}

// Close closes the cache database connection
func (c *Cache) Close() error {
	if c.db != nil {
		log.Println("[CACHE] closing cache database connection")
		return c.db.Close()
	}
	return nil
}

func New(basePath string, maxSizeBytes int64, maxObjectSize int64, purgeInterval time.Duration, orphanCleanupAge time.Duration, sourceDb *resilient.ResilientDatabase) (*Cache, error) {
	basePath = filepath.Clean(strings.TrimSpace(basePath))
	if basePath == "" {
		return nil, fmt.Errorf("cache base path cannot be empty")
	}

	dataDir := filepath.Join(basePath, DataDir)
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache data path %s: %w", dataDir, err)
	}

	dbPath := filepath.Join(basePath, IndexDB)
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open cache index DB: %w", err)
	}

	if _, err := db.Exec(`PRAGMA journal_mode = WAL;`); err != nil {
		// Log the warning, but allow to proceed as WAL is an optimization.
		log.Printf("[CACHE] WARNING: failed to set PRAGMA journal_mode = WAL: %v", err)
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
		}
		return nil, err
	}
	atomic.AddInt64(&c.cacheHits, 1)
	return data, nil
}

func (c *Cache) Put(contentHash string, data []byte) error {
	if int64(len(data)) > c.maxObjectSize {
		return fmt.Errorf("data size %d exceeds object limit %d", len(data), c.maxObjectSize)
	}

	path := c.GetPathForContentHash(contentHash)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	// Write to a temporary file first to minimize time holding the lock.
	// This also helps prevent corruption if the write is interrupted.
	tempFile, err := os.CreateTemp(dir, "put-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temporary cache file: %w", err)
	}
	defer os.Remove(tempFile.Name()) // Ensure temp file is cleaned up on return

	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close() // Attempt to close, but prioritize write error
		return fmt.Errorf("failed to write to temporary cache file: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary cache file: %w", err)
	}

	// Atomically move the file into its final location.
	if err := os.Rename(tempFile.Name(), path); err != nil {
		// If rename fails because the file exists, it means another process cached it. This is not an error.
		if !os.IsExist(err) {
			return fmt.Errorf("failed to move temporary file to final cache location %s: %w", path, err)
		}
		log.Printf("[CACHE] file %s appeared during rename, assuming concurrent cache success", path)
	}

	// Now, acquire lock just to update the index.
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.trackFile(path); err != nil {
		// The file exists, but we failed to track it. The next purge/sync cycle might fix it.
		// We don't remove the file here because it might be a valid cache entry from a concurrent Put.
		return fmt.Errorf("failed to track cache file %s: %w", path, err)
	}
	log.Printf("[CACHE] cached %s", path)
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
		log.Printf("[CACHE] failed to query index for existence of %s: %v", path, err)
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
			log.Printf("[CACHE] failed to remove cache file %s: %v\n", path, err)
			return fmt.Errorf("failed to remove cache file %s: %w", path, err)
		}
	}
	// Always try to remove from index, even if file was already gone.
	if _, err := c.db.Exec(`DELETE FROM cache_index WHERE path = ?`, path); err != nil {
		// Log the error, as this means the index might be out of sync.
		log.Printf("[CACHE] failed to remove index entry for path %s: %v\n", path, err)
		return fmt.Errorf("failed to remove index entry for path %s: %w", path, err)
	}
	return nil
}

func (c *Cache) MoveIn(path string, contentHash string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	target := c.GetPathForContentHash(contentHash)
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		log.Printf("[CACHE] failed to create target directory %s: %v\n", filepath.Dir(target), err)
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	// Try rename first (fast path)
	if err := os.Rename(path, target); err != nil {
		// If rename fails, check for specific conditions.
		if os.IsExist(err) {
			// This can happen on some OSes (like Windows) if the target exists.
			// It can also happen if another process cached the file concurrently.
			// The file is already in the cache, so we just need to remove the source.
			log.Printf("[CACHE] file %s already exists in cache, removing source %s", target, path)
			if err := os.Remove(path); err != nil {
				log.Printf("[CACHE] failed to remove source file %s after finding existing cache entry: %v", path, err)
			}
		} else if isCrossDeviceError(err) {
			// Cross-device link error (common on Unix), fall back to copy+delete.
			log.Printf("[CACHE] cross-device link detected, falling back to copy+delete for %s to %s\n", path, target)
			if err := copyFile(path, target); err != nil {
				log.Printf("[CACHE] failed to copy file %s to %s: %v\n", path, target, err)
				return fmt.Errorf("failed to copy file into cache: %w", err)
			}
			if err := os.Remove(path); err != nil {
				log.Printf("[CACHE] failed to remove source file %s after copy: %v\n", path, err)
				// File was copied successfully, so continue with tracking.
			}
		} else {
			// Another type of error occurred.
			log.Printf("[CACHE] failed to move file %s to %s: %v\n", path, target, err)
			return fmt.Errorf("failed to move file into cache: %w", err)
		}
	}

	if err := c.trackFile(target); err != nil {
		log.Printf("[CACHE] failed to track file %s: %v. The file was moved but not tracked.", target, err)
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
	log.Println("[CACHE] starting disk sync")
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
				log.Printf("[CACHE] failed to get stat for %s during sync: %v", path, statErr)
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
		log.Printf("[CACHE] found %d files on disk, updating index...", len(files))
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
				log.Printf("[CACHE] error tracking file %s during sync: %v", f.path, err)
				// Continue, try to sync as much as possible
			}
		}

		if err := tx.Commit(); err != nil {
			c.mu.Unlock()
			return fmt.Errorf("failed to commit disk sync transaction: %w", err)
		}
		c.mu.Unlock()
		log.Printf("[CACHE] index update complete")
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
	log.Println("[CACHE] running cache purge cycle")
	if err := c.PurgeIfNeeded(ctx); err != nil {
		log.Printf("[CACHE] WARNING: cache purge failed: %v\n", err)
	}
	if err := c.RemoveStaleDBEntries(ctx); err != nil {
		log.Printf("[CACHE] stale file cleanup error: %v\n", err)
	}
	if err := c.PurgeOrphanedContentHashes(ctx); err != nil {
		log.Printf("[CACHE] orphan cleanup error: %v\n", err)
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
				log.Printf("[CACHE] path %s no longer exists, skipping: %v", path, err)
				return nil // Treat as skippable for this specific entry and continue walk
			}
			// For other errors encountered by WalkDir, propagate them to stop the walk.
			log.Printf("[CACHE] error walking path %s: %v", path, err)
			return err // Propagate other errors
		}
		if !d.IsDir() || path == dataDir {
			return nil
		}

		// Try to remove the directory — only works if it's empty
		removeErr := os.Remove(path)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && !isDirNotEmptyError(removeErr) {
			// Log unexpected errors during removal, but don't stop the walk.
			log.Printf("[CACHE] WARNING: unexpected error removing directory %s: %v", path, removeErr)
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
		log.Println("[CACHE] attempted to purge files, but none were successfully removed from filesystem")
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
		log.Printf("[CACHE] error during post-purge directory cleanup: %v", err)
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

	log.Printf("[CACHE] size: %d, exceeds capacity: %d. Identifying files to purge.", totalSize, c.capacity)
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
			log.Printf("[CACHE] error scanning purge candidate: %v", err)
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

	log.Printf("[CACHE] identified %d files to purge to free up at least %d bytes", len(pathsToPurge), amountToFree)
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
			log.Printf("[CACHE] failed to remove file during purge: %s, error: %v", path, err)
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
	args := make([]interface{}, len(paths))
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
	log.Printf("[CACHE] removed %d entries from index", rowsAffected)
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
			log.Printf("[CACHE] error scanning path: %v", err)
			continue
		}

		contentHash := filepath.Base(path)
		// Basic validation for a hash-like string, adjust if needed
		if len(contentHash) < 32 || len(contentHash) > 128 { // Example length check for typical hashes
			log.Printf("[CACHE] suspicious content hash from path %s: %s", path, contentHash)
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
		log.Printf("[CACHE] removed %d orphaned entries\n", purged)
	}

	return nil
}

func (c *Cache) purgeHashBatch(ctx context.Context, contentHashes []string, paths []string) int {
	// Phase 1: Check against the main database (slow network call, no lock needed).
	existingDBHashes, err := c.sourceDB.FindExistingContentHashesWithRetry(ctx, contentHashes)
	if err != nil {
		log.Printf("[CACHE] error finding existing content hashes from sourceDB: %v", err)
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
			log.Printf("[CACHE] error removing cached file %s: %v\n", path, err)
		}
	}

	if len(successfullyRemovedPaths) == 0 {
		return 0
	}

	// Batch delete from the SQLite index inside a transaction.
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("[CACHE] error beginning transaction: %v\n", err)
		return 0
	}
	defer tx.Rollback() // Rollback if not committed

	// SQLite doesn't support array parameters, so we build a query with placeholders.
	// This is safe as paths are generated internally, not from user input.
	query := `DELETE FROM cache_index WHERE path IN (?` + strings.Repeat(",?", len(successfullyRemovedPaths)-1) + `)`
	args := make([]interface{}, len(successfullyRemovedPaths))
	for i, p := range successfullyRemovedPaths {
		args[i] = p
	}

	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		log.Printf("[CACHE] error batch deleting from index: %v\n", err)
		return 0
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[CACHE] error committing transaction: %v\n", err)
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
			log.Printf("[CACHE] error scanning path during stale check: %v\n", err)
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

	// Phase 3: Remove stale entries from the index in a single batch (write, short lock).
	c.mu.Lock()
	defer c.mu.Unlock()

	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for stale entry removal: %w", err)
	}
	defer tx.Rollback()

	// Use the same batch delete pattern as other purge functions.
	query := `DELETE FROM cache_index WHERE path IN (?` + strings.Repeat(",?", len(stalePaths)-1) + `)`
	args := make([]interface{}, len(stalePaths))
	for i, p := range stalePaths {
		args[i] = p
	}

	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to batch delete stale entries from index: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit stale entry deletions: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	log.Printf("[CACHE] removed %d stale entries from index\n", rowsAffected)
	return nil
}

// Get path for a given content hash, by splitting the hash into 3 parts
func (c *Cache) GetPathForContentHash(contentHash string) string {
	// Require a minimum length for the hash to be splittable as intended.
	if len(contentHash) < 4 { // Adjusted minimum length
		log.Printf("[CACHE] received short contentHash '%s', using directly in data_dir path construction\n", contentHash)
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

	log.Println("[CACHE] purging all cached objects and clearing index")

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

	log.Println("[CACHE] purge complete")
	return nil
}

// GetRecentMessagesForWarmup is a helper method that delegates to the source database
// This provides a convenient way for higher-level services to get warmup data through the cache
func (c *Cache) GetRecentMessagesForWarmup(ctx context.Context, userID int64, mailboxNames []string, messageCount int) (map[string][]string, error) {
	return c.sourceDB.GetRecentMessagesForWarmupWithRetry(ctx, userID, mailboxNames, messageCount)
}
