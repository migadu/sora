// Package cache provides a local filesystem cache for frequently accessed S3 objects.
//
// The cache reduces latency and S3 API calls by maintaining local copies of
// message bodies that are accessed frequently. It includes:
//   - SQLite-based metadata tracking
//   - LRU eviction based on size limits
//   - Metrics for hit/miss ratios
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
// The IMAP server warms the cache when a user logs in ([local_cache] enable_warmup):
// it fetches the most recent messages of the configured mailboxes from S3 and puts
// them here.
package cache

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
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
}

const DataDir = "data"
const IndexDB = "cache_index.db"
const PurgeBatchSize = 1000
const NumShards = 256

// tmpInfix marks the temporary file a write puts next to its final path:
// <path>.tmp.<suffix>. Final names are hex and never hold it.
const tmpInfix = ".tmp."

// staleTmpAge is how old a temporary file must be before the shard sweep removes it: a
// write finishes with its file within seconds, so one this old was cut off by a crash.
const staleTmpAge = time.Hour

// ErrObjectTooLarge is returned when attempting to cache an object that exceeds the size
// limit: max_object_size, or one shard's share of the capacity (see tooLarge).
var ErrObjectTooLarge = errors.New("object size exceeds limit")

type cacheShard struct {
	db *sql.DB
	mu sync.Mutex
	// size is an upper bound on the bytes the shard's index tracks, guarded by mu. It is
	// measured when the shard is opened and by every purge of it, and grows with every
	// object tracked. Removals other than a purge's leave it high, which costs at most
	// one needless purge check.
	size int64
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
		dbPath := shardIndexPath(basePath, i)
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

		shard := &cacheShard{db: db}
		if err := db.QueryRow(`SELECT COALESCE(SUM(size), 0) FROM cache_index`).Scan(&shard.size); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to measure cache index for shard %s: %w", shardHex, err)
		}
		c.shards[i] = shard
	}

	if shardCapacity := maxSizeBytes / NumShards; maxObjectSize > shardCapacity {
		logger.Info("Cache: max_object_size is above one shard's share of the capacity (capacity/256); larger objects are not cached",
			"max_object_size", maxObjectSize, "effective_max_object_size", shardCapacity)
	}

	// No purge loop here: the server starts the one it runs with StartPurgeLoop, and
	// sora-admin opens the cache of a running server.
	go c.processAccessLog()
	return c, nil
}

// tooLarge reports whether an object of size bytes is refused: above max_object_size, or
// above its shard's share of the capacity. Capacity is enforced per shard, so an object
// larger than that share cannot stay cached: writing it would evict every other object
// of its shard and then the object itself.
func (c *Cache) tooLarge(size int64) bool {
	return size > c.maxObjectSize || size > c.capacity/NumShards
}

func shardIndexPath(basePath string, shard int) string {
	return filepath.Join(basePath, fmt.Sprintf("cache_index_%02x.db", shard))
}

// Usage returns the number of objects the index of the cache at basePath tracks and
// their total size. It opens the index read-only and changes nothing: no purge runs,
// and a path that holds no cache is an error rather than a new cache. (SQLite still
// creates an index's -wal and -shm files when no other connection, such as a running
// server's, has.) sora-admin reports on the cache of a running server with it.
func Usage(basePath string) (objects, totalSize int64, err error) {
	basePath = strings.TrimSpace(basePath)
	if basePath == "" {
		return 0, 0, fmt.Errorf("cache base path cannot be empty")
	}
	if basePath, err = filepath.Abs(basePath); err != nil {
		return 0, 0, err
	}
	for i := 0; i < NumShards; i++ {
		dbPath := shardIndexPath(basePath, i)
		if _, err := os.Stat(dbPath); err != nil {
			return 0, 0, fmt.Errorf("no cache index at %s: %w", dbPath, err)
		}
		dsn := (&url.URL{Scheme: "file", Path: dbPath, RawQuery: "mode=ro&_pragma=busy_timeout(5000)"}).String()
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			return 0, 0, fmt.Errorf("failed to open cache index %s: %w", dbPath, err)
		}
		var n, size int64
		err = db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(size), 0) FROM cache_index`).Scan(&n, &size)
		db.Close()
		if err != nil {
			return 0, 0, fmt.Errorf("failed to read cache index %s: %w", dbPath, err)
		}
		objects += n
		totalSize += size
	}
	return objects, totalSize, nil
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

// GetPathForContentHash returns the absolute filesystem path for a content hash:
// data/XX/YY/<rest of the hash>.
//
// The fan-out directories data/XX and data/XX/YY are created by the first write into them
// and never removed again (only PurgeAll removes them): a writer creates its directory and
// then puts its file into it, so removing a directory that looks empty would pull it out
// from under a writer in between, which then fails (#645). There are at most 256 × 256.
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

	// The file and its row go under the shard lock, as in every removal: a Put of the
	// object in between would otherwise lose its row and leave a file without one.
	shard.mu.Lock()
	err := os.Remove(path)
	if err != nil && !os.IsNotExist(err) {
		shard.mu.Unlock()
		return fmt.Errorf("failed to delete file: %w", err)
	}
	dbErr := deleteIndexRowLocked(context.Background(), shard, path)
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
// A file the cache does not take (see tooLarge) is refused with ErrObjectTooLarge and,
// as when the move itself fails, left for the caller to remove.
func (c *Cache) MoveIn(sourcePath string, contentHash string) error {
	if info, err := os.Stat(sourcePath); err == nil && c.tooLarge(info.Size()) {
		return ErrObjectTooLarge
	}

	targetPath := c.GetPathForContentHash(contentHash)
	shard := c.getShard(contentHash)

	if _, err := os.Stat(targetPath); err == nil {
		logger.Info("Cache: File already exists in cache - removing source", "target", targetPath, "source", sourcePath)
		_ = os.Remove(sourcePath)
		return c.trackPlaced(shard, targetPath)
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
		return fmt.Errorf("failed to create target directory: %w", err)
	}

	if err := os.Rename(sourcePath, targetPath); err != nil {
		if errors.Is(err, syscall.EXDEV) {
			if copyErr := c.copyAndRemove(sourcePath, targetPath); copyErr != nil {
				return copyErr
			}
			return c.trackPlaced(shard, targetPath)
		}
		return fmt.Errorf("failed to move file into cache: %w", err)
	}

	return c.trackPlaced(shard, targetPath)
}

// copyAndRemove is a fallback for os.Rename when crossing device boundaries (EXDEV)
func (c *Cache) copyAndRemove(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file for copy: %w", err)
	}
	defer sourceFile.Close()

	// Copy to a temporary name and rename: by the time MoveIn runs, the message row
	// is already marked uploaded, so a reader may open dst at any moment and must
	// never see it half-written.
	tmp := dst + tmpInfix + fmt.Sprintf("%d", time.Now().UnixNano())
	destFile, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create destination file for copy: %w", err)
	}
	if _, err := io.Copy(destFile, sourceFile); err != nil {
		destFile.Close()
		os.Remove(tmp)
		return fmt.Errorf("failed to copy file contents: %w", err)
	}
	if err := destFile.Sync(); err != nil {
		destFile.Close()
		os.Remove(tmp)
		return fmt.Errorf("failed to fsync copied file: %w", err)
	}
	if err := destFile.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	sourceFile.Close()
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("failed to move copied file into place: %w", err)
	}

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
	if c.tooLarge(int64(len(data))) {
		return ErrObjectTooLarge
	}

	path := c.GetPathForContentHash(contentHash)

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create cache directory structure: %w", err)
	}

	// Write to temp file first to avoid partial reads by concurrent requests
	b := make([]byte, 4)
	rand.Read(b)
	tempPath := path + tmpInfix + fmt.Sprintf("%d_%x", time.Now().UnixNano(), b)
	file, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create cache file: %w", err)
	}
	defer func() {
		file.Close()
		os.Remove(tempPath) // Clean up temp file if rename fails
	}()

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write cache file: %w", err)
	}
	// Sync before the rename: a rename without it can, after a crash, leave the final
	// name pointing at a truncated file, which a reader would serve as the message.
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to fsync cache file: %w", err)
	}
	file.Close()

	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("failed to finalize cache file: %w", err)
	}

	shard := c.getShard(contentHash)
	return c.trackPlaced(shard, path)
}

// trackPlaced indexes a file Put or MoveIn has just put in place at path, and removes it
// again when the index does not take it. Every eviction starts from the index and Get
// serves the file without looking at it, so a file left without its row would stay on
// disk for good, outside the capacity (#768). The body is content-addressed: the next
// miss fetches it again.
func (c *Cache) trackPlaced(shard *cacheShard, path string) error {
	err := c.trackFile(shard, path)
	if err != nil {
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			logger.Warn("Cache: Failed to remove a file the index did not take", "path", path, "error", rmErr)
		}
	}
	return err
}

func deleteIndexRowLocked(ctx context.Context, shard *cacheShard, path string) error {
	var oldSize int64
	hasOld := shard.db.QueryRowContext(ctx, `SELECT size FROM cache_index WHERE path = ?`, path).Scan(&oldSize) == nil
	res, err := shard.db.ExecContext(ctx, `DELETE FROM cache_index WHERE path = ?`, path)
	if err != nil {
		return err
	}
	if hasOld {
		if n, _ := res.RowsAffected(); n > 0 {
			shard.size -= oldSize
		}
	}
	return nil
}

func (c *Cache) trackFile(shard *cacheShard, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat file for tracking: %w", err)
	}

	now := time.Now()
	// Best-effort sync of on-disk mtime with placement time so a later crash-recovery
	// sweep (sweepShardFiles) does not see an older staging mtime either.
	_ = os.Chtimes(path, now, now)

	shardCapacity := c.capacity / NumShards
	shard.mu.Lock()
	var oldSize int64
	_ = shard.db.QueryRow(`SELECT size FROM cache_index WHERE path = ?`, path).Scan(&oldSize)
	_, err = shard.db.Exec(
		`INSERT OR REPLACE INTO cache_index (path, size, mod_time) VALUES (?, ?, ?)`,
		path, info.Size(), now,
	)
	if err == nil {
		shard.size += info.Size() - oldSize
	}
	full := shard.size > shardCapacity
	shard.mu.Unlock()

	if err != nil {
		return fmt.Errorf("failed to update cache index: %w", err)
	}

	// Hold the capacity as objects come in, not only at the next purge cycle: that runs
	// every purge_interval, and the uploader moves every body it uploads in.
	if full {
		if err := c.purgeShardIfNeeded(context.Background(), shard, shardCapacity); err != nil {
			logger.Warn("Cache: Purge after write failed", "error", err)
		}
	}

	return nil
}

// StartPurgeLoop runs a purge cycle at once and then every purge interval, until ctx
// is done or the cache is closed. The server starts it once; New does not.
func (c *Cache) StartPurgeLoop(ctx context.Context) {
	go func() {
		// Each cycle sweeps one shard, so all 256 take 256 purge intervals (128 days at
		// the default 12h). The rotation follows the clock rather than starting over at
		// shard 00: a node restarted more often than that would otherwise sweep its first
		// few shards again and again and never the rest.
		staleShardIdx := 0
		if c.purgeInterval > 0 {
			staleShardIdx = int(time.Now().UnixNano() / int64(c.purgeInterval) % NumShards)
		}
		c.runPurgeCycle(ctx, &staleShardIdx)

		ticker := time.NewTicker(c.purgeInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-c.stopChan:
				return
			case <-ticker.C:
				c.runPurgeCycle(ctx, &staleShardIdx)
			}
		}
	}()
}

func (c *Cache) runPurgeCycle(ctx context.Context, staleShardIdx *int) {
	logger.Info("Cache: running cache purge cycle")

	// The shard's sweep comes first, so this cycle's capacity purge covers what it indexed.
	shard := c.shards[*staleShardIdx]
	if err := c.removeStaleEntriesForShard(ctx, shard); err != nil {
		logger.Error("Cache: Stale DB entry cleanup error for shard", "error", err, "shard", *staleShardIdx)
	}
	if err := c.sweepShardFiles(ctx, *staleShardIdx); err != nil {
		logger.Error("Cache: File sweep error for shard", "error", err, "shard", *staleShardIdx)
	}

	if err := c.PurgeIfNeeded(ctx); err != nil {
		logger.Warn("Cache: Purge failed", "error", err)
	}
	if err := c.PurgeOrphanedContentHashes(ctx); err != nil {
		logger.Error("Cache: Orphan cleanup error", "error", err)
	}

	*staleShardIdx = (*staleShardIdx + 1) % NumShards
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

	for _, item := range pathsToPurge {
		shard.mu.Lock()
		removeErr := os.Remove(item.path)
		if removeErr != nil && !os.IsNotExist(removeErr) {
			logger.Warn("Cache: Failed to delete file during purge", "path", item.path, "error", removeErr)
			shard.mu.Unlock()
			continue
		}
		res, dbErr := shard.db.ExecContext(ctx, `DELETE FROM cache_index WHERE path = ?`, item.path)
		if dbErr == nil {
			// Only the purge that removed the row counts it: two purges of a shard can
			// pick the same candidates.
			if n, _ := res.RowsAffected(); n > 0 {
				shard.size -= item.size
			}
		}
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
	shard.size = currentSize

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

// PurgeAll empties the cache. The index is cleared before the files are removed: a write
// landing in between then leaves at most a row without its file, which the stale-entry
// sweep drops and Get treats as a miss, never a file whose row the clearing drops, which
// no eviction would ever reach (#768).
func (c *Cache) PurgeAll(ctx context.Context) error {
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
			} else {
				shard.size = 0
			}
			shard.mu.Unlock()
		}(c.shards[i])
	}
	wg.Wait()

	dataDir := filepath.Join(c.basePath, DataDir)
	entries, err := os.ReadDir(dataDir)
	if err != nil && !os.IsNotExist(err) {
		errs = append(errs, fmt.Errorf("failed to read cache data directory: %w", err))
	} else if err == nil {
		for _, entry := range entries {
			if entry.IsDir() && len(entry.Name()) == 2 {
				fullPath := filepath.Join(dataDir, entry.Name())
				if err := os.RemoveAll(fullPath); err != nil {
					logger.Error("Cache: Failed to remove directory during PurgeAll", "path", fullPath, "error", err)
					errs = append(errs, fmt.Errorf("failed to remove cache directory %s: %w", fullPath, err))
					// The index was cleared first to cover racing writers. If removing a
					// shard only partly succeeded, put its remaining bodies back into the
					// index now rather than waiting for its next periodic sweep.
					hi, lo := hexCharToByte(entry.Name()[0]), hexCharToByte(entry.Name()[1])
					if hi < 16 && lo < 16 {
						if err := c.sweepShardFiles(ctx, int(hi<<4|lo)); err != nil {
							errs = append(errs, fmt.Errorf("failed to re-index cache directory %s: %w", fullPath, err))
						}
					}
				}
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to purge cache, encountered %d errors: %w", len(errs), errors.Join(errs...))
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
				// The row goes only with its file, and both under the shard lock, as in
				// the capacity purge: a row dropped next to a file that stays (a failed
				// remove, or a Put of the object in between) leaves that file outside
				// every eviction (#768).
				shard.mu.Lock()
				if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
					shard.mu.Unlock()
					logger.Warn("Cache: Failed to delete orphaned file", "path", p, "error", err)
					continue
				}
				_ = deleteIndexRowLocked(ctx, shard, p)
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
		// Checked again under the lock: a Put of the object may have put its file back
		// since, and its row must stay with it (#768).
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			_ = deleteIndexRowLocked(ctx, shard, p)
		}
		shard.mu.Unlock()
	}
	return nil
}

// sweepShardFiles walks shard idx's directory data/XX for what the index lost: a file
// under its final name without a row is indexed, so the capacity and the orphan purge
// cover it again, and a temporary file older than staleTmpAge is removed. A write cut off
// by a crash leaves them (one between its rename and its index insert, one before its
// rename); nothing else reaches them, as every eviction starts from the index and Get
// serves a file without indexing it (#768). Directories stay (#645).
func (c *Cache) sweepShardFiles(ctx context.Context, idx int) error {
	shard := c.shards[idx]

	shard.mu.Lock()
	rows, err := shard.db.QueryContext(ctx, `SELECT path FROM cache_index`)
	shard.mu.Unlock()
	if err != nil {
		return fmt.Errorf("failed to query cache index: %w", err)
	}
	indexed := make(map[string]struct{})
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err == nil {
			indexed[p] = struct{}{}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed to read cache index: %w", err)
	}

	var added, addedSize int64
	var removedTmp int
	staleBefore := time.Now().Add(-staleTmpAge)
	dir := filepath.Join(c.basePath, DataDir, fmt.Sprintf("%02x", idx))
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if !os.IsNotExist(err) {
				logger.Warn("Cache: Failed to read path during file sweep", "path", path, "error", err)
			}
			return nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if strings.Contains(d.Name(), tmpInfix) {
			if info, err := d.Info(); err == nil && info.ModTime().Before(staleBefore) {
				if err := os.Remove(path); err == nil {
					removedTmp++
				} else if !os.IsNotExist(err) {
					logger.Warn("Cache: Failed to remove stale temporary file", "path", path, "error", err)
				}
			}
			return nil
		}
		if _, ok := indexed[path]; ok {
			return nil
		}
		// Under the lock, as every removal takes its file and row under it: a file
		// removed since is not indexed again.
		shard.mu.Lock()
		defer shard.mu.Unlock()
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		res, err := shard.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO cache_index (path, size, mod_time) VALUES (?, ?, ?)`,
			path, info.Size(), info.ModTime())
		if err != nil {
			logger.Warn("Cache: Failed to index file during file sweep", "path", path, "error", err)
			return nil
		}
		if n, _ := res.RowsAffected(); n > 0 {
			shard.size += info.Size()
			added++
			addedSize += info.Size()
		}
		return nil
	})
	if added > 0 || removedTmp > 0 {
		logger.Info("Cache: File sweep took back files the index lost", "shard", fmt.Sprintf("%02x", idx),
			"indexed", added, "indexed_bytes", addedSize, "removed_tmp", removedTmp)
	}
	return err
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
