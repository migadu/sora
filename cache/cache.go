package cache

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/migadu/sora/db"
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
	sourceDB         *db.Database
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

func New(basePath string, maxSizeBytes int64, maxObjectSize int64, purgeInterval time.Duration, orphanCleanupAge time.Duration, sourceDb *db.Database) (*Cache, error) {
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
	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		atomic.AddInt64(&c.cacheMisses, 1)
		return false, nil
	}
	if err == nil {
		atomic.AddInt64(&c.cacheHits, 1)
	}
	return err == nil, err
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
	if err := os.Rename(path, target); err != nil {
		log.Printf("[CACHE] failed to move file %s to %s: %v\n", path, target, err)
		return fmt.Errorf("failed to move file into cache: %w", err)
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

func (c *Cache) PurgeIfNeeded(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	dataDir := filepath.Join(c.basePath, DataDir)
	var nullTotalSize sql.NullInt64
	row := c.db.QueryRow(`SELECT SUM(size) FROM cache_index`)
	if err := row.Scan(&nullTotalSize); err != nil {
		// An error here (other than sql.ErrNoRows, which Scan handles for Null types) is problematic.
		return fmt.Errorf("failed to get total cache size: %w", err)
	}
	var totalSize int64
	if nullTotalSize.Valid {
		totalSize = nullTotalSize.Int64
	}

	if totalSize <= c.capacity {
		log.Printf("[CACHE] size: %d, within capacity: %d\n", totalSize, c.capacity)
		return nil
	}

	log.Printf("[CACHE] size: %d, exceeds capacity: %d\n", totalSize, c.capacity)

	rows, err := c.db.Query(`SELECT path, size FROM cache_index ORDER BY mod_time ASC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var freed int64
	for rows.Next() {
		var path string
		var size int64
		if err := rows.Scan(&path, &size); err != nil { // Log if scan fails
			log.Printf("[CACHE] error scanning row during purge: %v\n", err)
			continue
		}
		if err := os.Remove(path); err == nil {
			if _, dbErr := c.db.Exec(`DELETE FROM cache_index WHERE path = ?`, path); dbErr != nil {
				log.Printf("[CACHE] failed to delete index entry for %s: %v", path, dbErr)
			}
			freed += size
			removeEmptyParents(path, dataDir)
			if (totalSize - freed) <= c.capacity {
				log.Printf("[CACHE] freed %d bytes, total size now: %d bytes\n", freed, totalSize-freed)
				break
			}
		}
	}
	if err := c.cleanupStaleDirectories(); err != nil {
		log.Printf("[CACHE] error during cleanupStaleDirectories: %v", err)
	}
	return nil
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

func (c *Cache) SyncFromDisk() error {
	var filePaths []string

	dataDir := filepath.Join(c.basePath, DataDir)
	err := filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			filePaths = append(filePaths, path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk cache directory: %w", err)
	}

	for _, path := range filePaths {
		c.mu.Lock()
		if err := c.trackFile(path); err != nil {
			log.Printf("[CACHE] error tracking file %s: %v", path, err)
		}
		c.mu.Unlock()
	}

	ctx := context.Background()
	if err := c.RemoveStaleDBEntries(ctx); err != nil {
		return fmt.Errorf("failed to remove stale DB entries: %w", err)
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

func (c *Cache) PurgeOrphanedContentHashes(ctx context.Context) error {
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

		if len(batch) == PurgeBatchSize {
			purged += c.purgeHashBatch(ctx, batch, paths)
			batch = nil
			paths = nil
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
	dataDir := filepath.Join(c.basePath, DataDir)
	existingDBHashes, err := c.sourceDB.FindExistingContentHashes(ctx, contentHashes) // This DB method needs to be created
	if err != nil {
		log.Printf("[CACHE] error finding existing content hashes from sourceDB: %v", err)
		return 0
	}

	existsMap := make(map[string]bool)
	for _, hash := range existingDBHashes {
		existsMap[hash] = true
	}
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		log.Printf("[CACHE] error beginning transaction: %v\n", err)
		return 0 // Cannot proceed without a transaction for DB deletes
	}
	defer tx.Rollback() // Rollback if not committed

	purged := 0
	for i, currentHash := range contentHashes {
		if !existsMap[currentHash] {
			// Attempt to remove the file first
			err := os.Remove(paths[i])
			fileRemovedOrNotExists := err == nil || os.IsNotExist(err)

			if err != nil && !os.IsNotExist(err) {
				log.Printf("[CACHE] error removing cached file %s: %v\n", paths[i], err)
				// If file removal failed for a reason other than "not exist",
				// skip deleting the DB entry to avoid orphaning the DB record.
				continue
			}

			// If file was successfully removed or didn't exist, try to remove the DB entry.
			if fileRemovedOrNotExists {
				_, dbErr := tx.ExecContext(ctx, `DELETE FROM cache_index WHERE path = ?`, paths[i])
				if dbErr != nil {
					log.Printf("[CACHE] error deleting cache index entry for path %s: %v\n", paths[i], dbErr)
					// Log the error and continue. The transaction will attempt to commit other successful deletes.
					// This might leave an orphaned file if os.Remove succeeded but DB delete failed,
					// but RemoveStaleDBEntries might catch it later if the file is truly gone.
					continue
				}
				removeEmptyParents(paths[i], dataDir) // Only remove parents if both file and DB entry are handled.
				purged++
			}
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[CACHE] error committing transaction: %v\n", err)
		return 0 // Return 0 as the batch operation wasn't fully successful
	}
	return purged
}

func (c *Cache) RemoveStaleDBEntries(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	rows, err := c.db.QueryContext(ctx, `SELECT path FROM cache_index`)
	if err != nil {
		return fmt.Errorf("failed to query cache_index: %w", err)
	}
	defer rows.Close()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback() // safe to call even if tx is already committed

	var removed int
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			log.Printf("[CACHE] error scanning path: %v\n", err)
			continue
		}
		if _, err := os.Stat(path); os.IsNotExist(err) {
			_, err = tx.ExecContext(ctx, `DELETE FROM cache_index WHERE path = ?`, path)
			if err != nil {
				log.Printf("[CACHE] failed to delete index entry for path %s: %v\n", path, err)
				// Continue to try and remove other stale entries
			}
			removed++
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit deletions: %w", err)
	}

	if removed > 0 {
		log.Printf("[CACHE] removed %d stale entries\n", removed)
	}

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

	// Get all cached file paths
	rows, err := c.db.QueryContext(ctx, `SELECT path FROM cache_index`)
	if err != nil {
		return fmt.Errorf("failed to query cache index: %w", err)
	}
	defer rows.Close()

	var paths []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			log.Printf("[CACHE] error scanning path during purge: %v", err)
			continue
		}
		paths = append(paths, path)
	}

	// Remove all files
	dataDir := filepath.Join(c.basePath, DataDir)
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Printf("[CACHE] failed to remove file %s: %v", path, err)
		}
		removeEmptyParents(path, dataDir)
	}

	// Clear the cache index
	if _, err := c.db.ExecContext(ctx, `DELETE FROM cache_index`); err != nil {
		return fmt.Errorf("failed to clear cache index: %w", err)
	}

	// Clean up any remaining empty directories
	if err := c.cleanupStaleDirectories(); err != nil {
		log.Printf("[CACHE] error during cleanupStaleDirectories: %v", err)
	}

	return nil
}

// GetRecentMessagesForWarmup is a helper method that delegates to the source database
// This provides a convenient way for higher-level services to get warmup data through the cache
func (c *Cache) GetRecentMessagesForWarmup(ctx context.Context, userID int64, mailboxNames []string, messageCount int) (map[string][]string, error) {
	return c.sourceDB.GetRecentMessagesForWarmup(ctx, userID, mailboxNames, messageCount)
}
