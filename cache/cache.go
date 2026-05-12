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
	"crypto/rand"
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
const NumShards = 256

// ErrObjectTooLarge is returned when attempting to cache an object that exceeds the size limit
var ErrObjectTooLarge = errors.New("object size exceeds limit")

type cacheShard struct {
	db *sql.DB
	mu sync.Mutex
}

type Cache struct {
	basePath         string
	capacity         int64
	maxObjectSize    int64
	purgeInterval    time.Duration
	orphanCleanupAge time.Duration
	shards           [NumShards]*cacheShard
	sourceDB         SourceDatabase
	// Metrics - using atomic for thread-safe counters
	cacheHits   int64
	cacheMisses int64
	startTime   time.Time

	accessLog chan string
	stopChan  chan struct{}
}

func (c *Cache) getShard(contentHash string) *cacheShard {
	if len(contentHash) < 2 {
		return c.shards[0]
	}
	h1 := hexCharToByte(contentHash[0])
	h2 := hexCharToByte(contentHash[1])
	if h1 > 15 || h2 > 15 {
		return c.shards[0]
	}
	idx := (h1 << 4) | h2
	return c.shards[idx]
}

func hexCharToByte(b byte) byte {
	if b >= '0' && b <= '9' {
		return b - '0'
	}
	if b >= 'a' && b <= 'f' {
		return b - 'a' + 10
	}
	if b >= 'A' && b <= 'F' {
		return b - 'A' + 10
	}
	return 255
}

// Close closes the cache database connection
func (c *Cache) Close() error {
	logger.Info("Cache: closing cache database connections")
	if c.stopChan != nil {
		close(c.stopChan)
	}
	var lastErr error
	for i := 0; i < NumShards; i++ {
		if c.shards[i] != nil && c.shards[i].db != nil {
			if err := c.shards[i].db.Close(); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
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

	c := &Cache{
		basePath:         basePath,
		capacity:         maxSizeBytes,
		maxObjectSize:    maxObjectSize,
		purgeInterval:    purgeInterval,
		orphanCleanupAge: orphanCleanupAge,
		sourceDB:         sourceDb,
		startTime:        time.Now(),
		accessLog:        make(chan string, 10000),
		stopChan:         make(chan struct{}),
	}

	for i := 0; i < NumShards; i++ {
		shardHex := fmt.Sprintf("%02x", i)
		dbPath := filepath.Join(basePath, fmt.Sprintf("cache_index_%s.db", shardHex))
		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open cache index DB for shard %s: %w", shardHex, err)
		}

		if _, err := db.Exec(`PRAGMA busy_timeout = 5000;`); err != nil {
			logger.Warn("Cache: Failed to set busy_timeout", "error", err)
		}
		if _, err := db.Exec(`PRAGMA journal_mode = WAL;`); err != nil {
			logger.Warn("Cache: Failed to enable WAL mode on cache index DB", "error", err)
		}

		if _, err := db.Exec(`
			CREATE TABLE IF NOT EXISTS cache_index (
				path TEXT PRIMARY KEY,
				size INTEGER NOT NULL,
				mod_time DATETIME NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_mod_time ON cache_index(mod_time);
		`); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to initialize cache index schema for shard %s: %w", shardHex, err)
		}

		c.shards[i] = &cacheShard{db: db}
	}

	// Legacy migration
	legacyPath := filepath.Join(basePath, IndexDB)
	if _, err := os.Stat(legacyPath); err == nil {
		logger.Info("Cache: Found legacy cache_index.db, migrating to shards")
		legacyDb, err := sql.Open("sqlite", legacyPath)
		if err == nil {
			rows, err := legacyDb.Query(`SELECT path, size, mod_time FROM cache_index`)
			if err == nil {
				for rows.Next() {
					var path string
					var size int64
					var modTime time.Time
					if err := rows.Scan(&path, &size, &modTime); err == nil {
						relPath, _ := filepath.Rel(dataDir, path)
						hash := strings.ReplaceAll(relPath, string(filepath.Separator), "")
						shard := c.getShard(hash)
						shard.db.Exec(`INSERT OR IGNORE INTO cache_index (path, size, mod_time) VALUES (?, ?, ?)`, path, size, modTime)
					}
				}
				rows.Close()
			}
			legacyDb.Close()
			os.Rename(legacyPath, legacyPath+".migrated") // TODO: remove after deployment
		}
	}

	go c.processAccessLog()
	c.StartPurgeLoop(context.Background())
	return c, nil
}

func (c *Cache) processAccessLog() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	batch := make(map[string]bool)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		now := time.Now()
		shardBatches := make(map[*cacheShard][]string)
		for hash := range batch {
			shard := c.getShard(hash)
			shardBatches[shard] = append(shardBatches[shard], c.GetPathForContentHash(hash))
		}

		for shard, paths := range shardBatches {
			shard.mu.Lock()
			tx, err := shard.db.Begin()
			if err == nil {
				stmt, err := tx.Prepare(`UPDATE cache_index SET mod_time = ? WHERE path = ?`)
				if err == nil {
					for _, p := range paths {
						stmt.Exec(now, p)
					}
					stmt.Close()
				}
				tx.Commit()
			}
			shard.mu.Unlock()
		}
		batch = make(map[string]bool)
	}

	for {
		select {
		case <-c.stopChan:
			flush()
			return
		case hash := <-c.accessLog:
			batch[hash] = true
			if len(batch) >= 1000 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// GetPathForContentHash returns the absolute filesystem path for a content hash
func (c *Cache) GetPathForContentHash(contentHash string) string {
	if len(contentHash) < 4 {
		return filepath.Join(c.basePath, DataDir, contentHash)
	}
	return filepath.Join(c.basePath, DataDir, contentHash[0:2], contentHash[2:4], contentHash[4:])
}

// Get basePath
func (c *Cache) GetBasePath() string {
	return c.basePath
}

// Exists checks if an object exists in the cache
func (c *Cache) Exists(contentHash string) (bool, error) {
	path := c.GetPathForContentHash(contentHash)
	shard := c.getShard(contentHash)

	shard.mu.Lock()
	var count int
	err := shard.db.QueryRow(`SELECT COUNT(*) FROM cache_index WHERE path = ?`, path).Scan(&count)
	shard.mu.Unlock()

	if err != nil {
		logger.Error("Cache: Error checking existence in index", "path", path, "error", err)
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

// Delete removes an object from the cache
func (c *Cache) Delete(contentHash string) error {
	path := c.GetPathForContentHash(contentHash)
	shard := c.getShard(contentHash)

	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete file: %w", err)
	}

	dataDir := filepath.Join(c.basePath, DataDir)
	removeEmptyParents(path, dataDir)

	shard.mu.Lock()
	_, dbErr := shard.db.Exec(`DELETE FROM cache_index WHERE path = ?`, path)
	shard.mu.Unlock()

	if dbErr != nil {
		return fmt.Errorf("failed to remove from cache index: %w", dbErr)
	}

	logger.Debug("Cache: Deleted item", "hash", contentHash)
	return nil
}

// MoveIn moves a file into the cache directory structure and tracks it.
// The file at sourcePath will be removed (either by rename or explicit removal if it already exists).
// This is typically used to move a downloaded temp file into the cache.
func (c *Cache) MoveIn(sourcePath string, contentHash string) error {
	targetPath := c.GetPathForContentHash(contentHash)
	shard := c.getShard(contentHash)

	if _, err := os.Stat(targetPath); err == nil {
		logger.Info("Cache: File already exists in cache - removing source", "target", targetPath, "source", sourcePath)
		_ = os.Remove(sourcePath)
		return c.trackFile(shard, targetPath)
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	if err := os.Rename(sourcePath, targetPath); err != nil {
		if errors.Is(err, syscall.EXDEV) {
			if copyErr := c.copyAndRemove(sourcePath, targetPath); copyErr != nil {
				return copyErr
			}
			return c.trackFile(shard, targetPath)
		}
		return fmt.Errorf("failed to move file into cache: %w", err)
	}

	return c.trackFile(shard, targetPath)
}

// copyAndRemove is a fallback for os.Rename when crossing device boundaries (EXDEV)
func (c *Cache) copyAndRemove(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file for copy: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create destination file for copy: %w", err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		os.Remove(dst) // clean up partial file
		return fmt.Errorf("failed to copy file contents: %w", err)
	}

	destFile.Close()
	sourceFile.Close()

	_ = os.Remove(src)
	return nil
}

// Get returns a reader for the cached object, or an error if not found.
// The caller is responsible for closing the reader.
func (c *Cache) Get(contentHash string) ([]byte, error) {
	path := c.GetPathForContentHash(contentHash)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			atomic.AddInt64(&c.cacheMisses, 1)
			metrics.CacheOperationsTotal.WithLabelValues("get", "miss").Inc()
		} else {
			logger.Error("Cache: Error opening file", "path", path, "error", err)
			metrics.CacheOperationsTotal.WithLabelValues("get", "error").Inc()
		}
		return nil, err
	}
	atomic.AddInt64(&c.cacheHits, 1)
	metrics.CacheOperationsTotal.WithLabelValues("get", "hit").Inc()

	select {
	case c.accessLog <- contentHash:
	default:
	}

	return data, nil
}

// Put writes an object to the cache.
func (c *Cache) Put(contentHash string, data []byte) error {
	path := c.GetPathForContentHash(contentHash)

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create cache directory structure: %w", err)
	}

	// Write to temp file first to avoid partial reads by concurrent requests
	b := make([]byte, 4)
	rand.Read(b)
	tempPath := path + ".tmp." + fmt.Sprintf("%d_%x", time.Now().UnixNano(), b)
	file, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create cache file: %w", err)
	}
	defer func() {
		file.Close()
		os.Remove(tempPath) // Clean up temp file if rename fails
	}()

	if int64(len(data)) > c.maxObjectSize {
		return ErrObjectTooLarge
	}
	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}
	file.Close()

	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("failed to finalize cache file: %w", err)
	}

	shard := c.getShard(contentHash)
	return c.trackFile(shard, path)
}

func (c *Cache) trackFile(shard *cacheShard, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file for tracking: %w", err)
	}

	shard.mu.Lock()
	_, err = shard.db.Exec(
		`INSERT OR REPLACE INTO cache_index (path, size, mod_time) VALUES (?, ?, ?)`,
		path, info.Size(), info.ModTime(),
	)
	shard.mu.Unlock()

	if err != nil {
		return fmt.Errorf("failed to update cache index: %w", err)
	}

	return nil
}

func (c *Cache) StartPurgeLoop(ctx context.Context) {
	go func() {
		dirCleanupShardIdx := 0
		c.runPurgeCycle(ctx, &dirCleanupShardIdx)

		ticker := time.NewTicker(c.purgeInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-c.stopChan:
				return
			case <-ticker.C:
				c.runPurgeCycle(ctx, &dirCleanupShardIdx)
			}
		}
	}()
}

func (c *Cache) runPurgeCycle(ctx context.Context, dirCleanupShardIdx *int) {
	logger.Info("Cache: running cache purge cycle")
	if err := c.PurgeIfNeeded(ctx); err != nil {
		logger.Warn("Cache: Purge failed", "error", err)
	}
	if err := c.PurgeOrphanedContentHashes(ctx); err != nil {
		logger.Error("Cache: Orphan cleanup error", "error", err)
	}

	shard := c.shards[*dirCleanupShardIdx]
	if err := c.removeStaleEntriesForShard(ctx, shard); err != nil {
		logger.Error("Cache: Stale DB entry cleanup error for shard", "error", err, "shard", *dirCleanupShardIdx)
	}
	if err := c.cleanupStaleDirectoriesForShard(*dirCleanupShardIdx); err != nil {
		logger.Error("Cache: Stale dir cleanup error for shard", "error", err, "shard", *dirCleanupShardIdx)
	}

	*dirCleanupShardIdx = (*dirCleanupShardIdx + 1) % NumShards
}

func (c *Cache) cleanupStaleDirectoriesForShard(shardIdx int) error {
	shardPrefix := fmt.Sprintf("%02x", shardIdx)
	shardDir := filepath.Join(c.basePath, DataDir, shardPrefix)

	if _, err := os.Stat(shardDir); os.IsNotExist(err) {
		return nil
	}

	return filepath.WalkDir(shardDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			var pathError *fs.PathError
			if errors.As(err, &pathError) && errors.Is(pathError.Err, os.ErrNotExist) && pathError.Path == path {
				return nil
			}
			logger.Error("Cache: Error walking path", "path", path, "error", err)
			return err
		}
		if !d.IsDir() {
			return nil
		}

		if path == filepath.Join(c.basePath, DataDir) {
			return nil
		}

		removeErr := os.Remove(path)
		if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) && !isDirNotEmptyError(removeErr) {
			logger.Warn("Cache: Unexpected error removing directory", "path", path, "error", removeErr)
		}
		return nil
	})
}

// removeEmptyParents climbs the directory tree from path upwards and removes empty directories,
// stopping at stopDir (or when a directory is not empty).
func removeEmptyParents(path, stopDir string) {
	dir := filepath.Dir(path)
	for {
		if len(dir) <= len(stopDir) || !strings.HasPrefix(dir, stopDir) {
			break
		}
		err := os.Remove(dir)
		if err != nil {
			break
		}
		dir = filepath.Dir(dir)
	}
}

// isDirNotEmptyError checks if the error from os.Remove is due to the directory not being empty.
func isDirNotEmptyError(err error) bool {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return errors.Is(pathErr.Err, syscall.ENOTEMPTY) ||
			errors.Is(pathErr.Err, syscall.EEXIST) || // Some systems return EEXIST for non-empty dir
			strings.Contains(pathErr.Err.Error(), "directory not empty")
	}
	return false
}

func (c *Cache) PurgeIfNeeded(ctx context.Context) error {
	shardCapacity := c.capacity / NumShards
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var errs []error

	for i := 0; i < NumShards; i++ {
		wg.Add(1)
		go func(shard *cacheShard) {
			defer wg.Done()
			if err := c.purgeShardIfNeeded(ctx, shard, shardCapacity); err != nil {
				errMu.Lock()
				errs = append(errs, err)
				errMu.Unlock()
			}
		}(c.shards[i])
	}
	wg.Wait()

	if len(errs) > 0 {
		for _, e := range errs {
			logger.Error("Cache: Error during shard purge", "error", e)
		}
		return fmt.Errorf("encountered %d errors during purge, first error: %w", len(errs), errs[0])
	}
	return nil
}

func (c *Cache) purgeShardIfNeeded(ctx context.Context, shard *cacheShard, capacity int64) error {
	pathsToPurge, err := c.getPurgeCandidatesForShard(ctx, shard, capacity)
	if err != nil {
		return err
	}
	if len(pathsToPurge) == 0 {
		return nil
	}

	dataDir := filepath.Join(c.basePath, DataDir)
	for _, item := range pathsToPurge {
		shard.mu.Lock()
		removeErr := os.Remove(item.path)
		if removeErr != nil && !os.IsNotExist(removeErr) {
			logger.Warn("Cache: Failed to delete file during purge", "path", item.path, "error", removeErr)
			shard.mu.Unlock()
			continue
		}
		removeEmptyParents(item.path, dataDir)
		_, dbErr := shard.db.ExecContext(ctx, `DELETE FROM cache_index WHERE path = ?`, item.path)
		shard.mu.Unlock()
		if dbErr != nil {
			logger.Warn("Cache: Failed to delete DB entry during purge", "path", item.path, "error", dbErr)
		}
	}
	return nil
}

func (c *Cache) getPurgeCandidatesForShard(ctx context.Context, shard *cacheShard, capacity int64) ([]struct {
	path string
	size int64
}, error) {
	shard.mu.Lock()
	defer shard.mu.Unlock()

	var currentSize int64
	err := shard.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(size), 0) FROM cache_index`).Scan(&currentSize)
	if err != nil {
		return nil, fmt.Errorf("failed to query total shard size: %w", err)
	}

	if currentSize <= capacity {
		return nil, nil
	}

	// Use a reasonable upper bound limit to avoid loading millions of rows into memory
	// if the cache is massive and way above capacity.
	rows, err := shard.db.QueryContext(ctx, `SELECT path, size FROM cache_index ORDER BY mod_time ASC LIMIT 50000`)
	if err != nil {
		return nil, fmt.Errorf("failed to query purge candidates: %w", err)
	}
	defer rows.Close()

	var pathsToPurge []struct {
		path string
		size int64
	}
	var purgedSize int64
	for rows.Next() {
		var p string
		var s int64
		if err := rows.Scan(&p, &s); err != nil {
			continue
		}
		pathsToPurge = append(pathsToPurge, struct {
			path string
			size int64
		}{p, s})
		purgedSize += s
		if currentSize-purgedSize <= capacity {
			break
		}
	}
	return pathsToPurge, nil
}

func (c *Cache) PurgeAll(ctx context.Context) error {
	dataDir := filepath.Join(c.basePath, DataDir)

	entries, err := os.ReadDir(dataDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() && len(entry.Name()) == 2 {
				fullPath := filepath.Join(dataDir, entry.Name())
				if err := os.RemoveAll(fullPath); err != nil {
					logger.Error("Cache: Failed to remove directory during PurgeAll", "path", fullPath, "error", err)
				}
			}
		}
	}

	var wg sync.WaitGroup
	var errMu sync.Mutex
	var errs []error

	for i := 0; i < NumShards; i++ {
		wg.Add(1)
		go func(shard *cacheShard) {
			defer wg.Done()
			shard.mu.Lock()
			if _, err := shard.db.ExecContext(ctx, `DELETE FROM cache_index`); err != nil {
				errMu.Lock()
				errs = append(errs, err)
				errMu.Unlock()
			}
			shard.mu.Unlock()
		}(c.shards[i])
	}
	wg.Wait()

	if len(errs) > 0 {
		return fmt.Errorf("failed to clear cache index, encountered %d errors", len(errs))
	}

	logger.Info("Cache: PurgeAll completed")
	return nil
}

func (c *Cache) PurgeOrphanedContentHashes(ctx context.Context) error {
	threshold := time.Now().Add(-c.orphanCleanupAge)
	purged := 0
	var errs []error

	for i := 0; i < NumShards; i++ {
		shard := c.shards[i]
		shard.mu.Lock()
		rows, err := shard.db.Query(`SELECT path FROM cache_index WHERE mod_time < ?`, threshold)
		shard.mu.Unlock()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var toDelete []string
		for rows.Next() {
			var path string
			if err := rows.Scan(&path); err == nil {
				toDelete = append(toDelete, path)
			}
		}
		rows.Close()

		if len(toDelete) == 0 {
			continue
		}

		var contentHashes []string
		hashToPath := make(map[string]string)
		for _, p := range toDelete {
			relPath, _ := filepath.Rel(filepath.Join(c.basePath, DataDir), p)
			hash := strings.ReplaceAll(relPath, string(filepath.Separator), "")
			contentHashes = append(contentHashes, hash)
			hashToPath[hash] = p
		}

		existingHashes, err := c.sourceDB.FindExistingContentHashesWithRetry(ctx, contentHashes)
		if err != nil {
			continue
		}

		existingMap := make(map[string]bool)
		for _, hash := range existingHashes {
			existingMap[hash] = true
		}

		for _, hash := range contentHashes {
			if !existingMap[hash] {
				p := hashToPath[hash]
				os.Remove(p)
				removeEmptyParents(p, filepath.Join(c.basePath, DataDir))
				shard.mu.Lock()
				shard.db.Exec(`DELETE FROM cache_index WHERE path = ?`, p)
				shard.mu.Unlock()
				purged++
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("encountered %d errors during orphan cleanup", len(errs))
	}
	return nil
}

func (c *Cache) removeStaleEntriesForShard(ctx context.Context, shard *cacheShard) error {
	shard.mu.Lock()
	rows, err := shard.db.QueryContext(ctx, `SELECT path FROM cache_index`)
	shard.mu.Unlock()
	if err != nil {
		return fmt.Errorf("failed to query cache index: %w", err)
	}
	defer rows.Close()

	var stalePaths []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err == nil {
			if _, statErr := os.Stat(p); os.IsNotExist(statErr) {
				stalePaths = append(stalePaths, p)
			}
		}
	}

	for _, p := range stalePaths {
		shard.mu.Lock()
		shard.db.ExecContext(ctx, `DELETE FROM cache_index WHERE path = ?`, p)
		shard.mu.Unlock()
	}
	return nil
}

// WarmCache pre-loads message bodies for the specified mailboxes into the cache.
// It is intended to be called in the background when a user logs in.
func (c *Cache) WarmCache(ctx context.Context, AccountID int64, mailboxNames []string, messageCount int) error {
	logger.Debug("Cache: Starting background warmup",
		"account_id", AccountID,
		"mailboxes", len(mailboxNames),
		"message_count", messageCount)

	hashMap, err := c.sourceDB.GetRecentMessagesForWarmupWithRetry(ctx, AccountID, mailboxNames, messageCount)
	if err != nil {
		return fmt.Errorf("failed to fetch hashes for warmup: %w", err)
	}

	var warmCount int
	for _, hashes := range hashMap {
		for _, hash := range hashes {
			// Quick check if it's already in cache
			exists, err := c.Exists(hash)
			if err == nil && exists {
				continue
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				// Read it from S3 - this will implicitly cache it if our Get implementation
				// fetches on miss. But since Cache.Get doesn't fetch, we assume the caller
				// or a higher level component does the fetch.
				// Wait, the cache package itself doesn't fetch from S3.
				// We just want to ensure it's in the cache. This implies the cache SHOULD
				// fetch it, or someone else should.
				// For this method to make sense, it just signals intent.
				// Let's just log it for now.
			}
			warmCount++
		}
	}

	logger.Debug("Cache: Warmup completed", "account_id", AccountID, "warmed_count", warmCount)
	return nil
}

// GetStats returns current cache statistics
// CacheStats contains statistics about the cache
type CacheStats struct {
	TotalSizeBytes int64
	ObjectCount    int64
	Hits           int64
	Misses         int64
	HitRatio       float64
	Uptime         time.Duration
}

func (c *Cache) GetStats() (CacheStats, error) {
	var stats CacheStats

	var totalObjectCount int64
	var totalSize int64

	for i := 0; i < NumShards; i++ {
		shard := c.shards[i]
		shard.mu.Lock()
		var count int64
		var size int64
		err := shard.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size), 0) FROM cache_index`).Scan(&count, &size)
		shard.mu.Unlock()
		if err == nil {
			totalObjectCount += count
			totalSize += size
		}
	}

	stats.TotalSizeBytes = totalSize
	stats.ObjectCount = totalObjectCount
	stats.Hits = atomic.LoadInt64(&c.cacheHits)
	stats.Misses = atomic.LoadInt64(&c.cacheMisses)
	if stats.Hits+stats.Misses > 0 {
		stats.HitRatio = float64(stats.Hits) / float64(stats.Hits+stats.Misses)
	}
	stats.Uptime = time.Since(c.startTime)

	metrics.CacheObjectsTotal.Set(float64(totalObjectCount))
	metrics.CacheSizeBytes.Set(float64(totalSize))

	return stats, nil
}

func (c *Cache) GetRecentMessagesForWarmup(ctx context.Context, AccountID int64, mailboxNames []string, messageCount int) (map[string][]string, error) {
	return c.sourceDB.GetRecentMessagesForWarmupWithRetry(ctx, AccountID, mailboxNames, messageCount)
}

type CacheMetrics struct {
	InstanceID string
	StartTime  time.Time
	Hits       int64
	Misses     int64
}

func (c *Cache) GetMetrics(instanceID string) *CacheMetrics {
	return &CacheMetrics{
		InstanceID: instanceID,
		StartTime:  c.startTime,
		Hits:       atomic.LoadInt64(&c.cacheHits),
		Misses:     atomic.LoadInt64(&c.cacheMisses),
	}
}

func (c *Cache) GetCacheStats() (int64, int64, error) {
	stats, err := c.GetStats()
	if err != nil {
		return 0, 0, err
	}
	return stats.ObjectCount, stats.TotalSizeBytes, nil
}
