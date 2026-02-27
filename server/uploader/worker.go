package uploader

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/storage"
)

// EmailAddress defines the methods needed from an email address object.
type EmailAddress interface {
	Domain() string
	LocalPart() string
}

// UploaderDB defines the database operations needed by the uploader worker.
// This interface makes the worker testable by allowing mocks.
type UploaderDB interface {
	AcquireAndLeasePendingUploadsWithRetry(ctx context.Context, instanceID string, batchSize int, retryInterval time.Duration, maxAttempts int) ([]db.PendingUpload, error)
	MarkUploadAttemptWithRetry(ctx context.Context, contentHash string, accountID int64) error
	GetPrimaryEmailForAccountWithRetry(ctx context.Context, accountID int64) (server.Address, error)
	IsContentHashUploadedWithRetry(ctx context.Context, contentHash string, accountID int64) (bool, error)
	CompleteS3UploadWithRetry(ctx context.Context, contentHash string, accountID int64) error
	PendingUploadExistsWithRetry(ctx context.Context, contentHash string, accountID int64) (bool, error)
	GetUploaderStatsWithRetry(ctx context.Context, maxAttempts int) (*db.UploaderStats, error)
	GetFailedUploadsWithRetry(ctx context.Context, maxAttempts int, limit int) ([]db.PendingUpload, error)
}

// UploaderS3 defines the S3 storage operations needed by the uploader worker.
type UploaderS3 interface {
	PutWithRetry(ctx context.Context, key string, reader io.Reader, size int64) error
}

// UploaderCache defines the cache operations needed by the uploader worker.
type UploaderCache interface {
	MoveIn(srcPath, contentHash string) error
}

type UploadWorker struct {
	rdb           UploaderDB
	s3            UploaderS3
	cache         UploaderCache
	path          string
	batchSize     int
	concurrency   int
	maxAttempts   int
	retryInterval time.Duration
	instanceID    string
	notifyCh      chan struct{}
	stopCh        chan struct{}
	errCh         chan<- error
	wg            sync.WaitGroup
	mu            sync.Mutex
	running       bool
}

func New(ctx context.Context, path string, batchSize int, concurrency int, maxAttempts int, retryInterval time.Duration, instanceID string, rdb *resilient.ResilientDatabase, s3 *storage.S3Storage, cache *cache.Cache, errCh chan<- error) (*UploadWorker, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, fmt.Errorf("failed to create local path %s: %w", path, err)
		}
	}
	// Wrap S3 storage with resilient patterns including circuit breakers
	resilientS3 := resilient.NewResilientS3Storage(s3)

	notifyCh := make(chan struct{}, 1)

	return &UploadWorker{
		rdb:           rdb,
		s3:            resilientS3,
		cache:         cache,
		errCh:         errCh,
		path:          path,
		batchSize:     batchSize,
		concurrency:   concurrency,
		maxAttempts:   maxAttempts,
		retryInterval: retryInterval,
		instanceID:    instanceID,
		notifyCh:      notifyCh,
		stopCh:        make(chan struct{}),
	}, nil
}

func (w *UploadWorker) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = true
	w.mu.Unlock()

	w.wg.Add(1)
	go w.run(ctx)

	logger.Info("Uploader: worker started")
	return nil
}

func (w *UploadWorker) run(ctx context.Context) {
	defer func() {
		w.mu.Lock()
		w.running = false
		w.mu.Unlock()
		w.wg.Done()
	}()

	monitorTicker := time.NewTicker(5 * time.Minute)
	defer monitorTicker.Stop()

	cleanupTicker := time.NewTicker(5 * time.Minute)
	defer cleanupTicker.Stop()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	logger.Info("Uploader: worker processing every 30s, cleanup and monitoring every 5min")

	// Process immediately on start
	w.processQueue(ctx)

	for {
		select {
		case <-ctx.Done():
			logger.Info("Uploader: worker stopped due to context cancellation")
			return
		case <-w.stopCh:
			logger.Info("Uploader: worker stopped due to stop signal")
			return
		case <-ticker.C:
			logger.Info("Uploader: timer tick")
			if err := w.processQueue(ctx); err != nil {
				w.reportError(err)
			}
		case <-monitorTicker.C:
			logger.Info("Uploader: monitor tick")
			if err := w.monitorStuckUploads(ctx); err != nil {
				logger.Error("Uploader: Monitor error", "error", err)
			}
		case <-cleanupTicker.C:
			logger.Info("Uploader: cleanup tick")
			if err := w.cleanupOrphanedFiles(ctx); err != nil {
				logger.Error("Uploader: Cleanup error", "error", err)
			}
		case <-w.notifyCh:
			logger.Info("Uploader: worker notified")
			_ = w.processQueue(ctx)
		}
	}
}

// Stop gracefully stops the worker and waits for all goroutines to complete.
// It is safe to call Stop multiple times - subsequent calls are no-ops if already stopped.
func (w *UploadWorker) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	w.running = false
	w.mu.Unlock()

	close(w.stopCh)
	w.wg.Wait()

	logger.Info("Uploader: worker stopped")
}

func (w *UploadWorker) NotifyUploadQueued() {
	select {
	case w.notifyCh <- struct{}{}:
	default:
		// Don't block if notifyCh already has a signal
	}
}

func (w *UploadWorker) processQueue(ctx context.Context) error {
	return w.processPendingUploads(ctx)
}

func (w *UploadWorker) processPendingUploads(ctx context.Context) error {
	sem := make(chan struct{}, w.concurrency)
	var wg sync.WaitGroup

	for {
		uploads, err := w.rdb.AcquireAndLeasePendingUploadsWithRetry(ctx, w.instanceID, w.batchSize, w.retryInterval, w.maxAttempts)
		if err != nil {
			return fmt.Errorf("failed to list pending uploads: %w", err)
		}

		// Track queue depth - critical for monitoring backpressure
		metrics.QueueDepth.WithLabelValues("s3_upload").Set(float64(len(uploads)))

		if len(uploads) == 0 {
			// Nothing to process, break and let the outer loop sleep
			break
		}

		for _, upload := range uploads {
			// Check if this upload has exceeded max attempts before processing
			if upload.Attempts >= w.maxAttempts {
				logger.Info("Uploader: Skipping upload due to excessive failed attempts", "hash", upload.ContentHash, "id", upload.ID, "attempts", upload.Attempts)
				continue // Skip this upload and move to the next one in the batch
			}

			select {
			case <-ctx.Done():
				logger.Info("Uploader: request aborted, waiting for in-flight uploads")
				wg.Wait()
				return nil
			case sem <- struct{}{}:
				wg.Add(1)
				go func(upload db.PendingUpload) {
					defer wg.Done()
					defer func() { <-sem }()
					w.processSingleUpload(ctx, upload)
				}(upload)
			}
		}
		wg.Wait()
	}
	return nil
}

func (w *UploadWorker) processSingleUpload(ctx context.Context, upload db.PendingUpload) {
	// Early validation of upload data
	if !isValidContentHash(upload.ContentHash) {
		logger.Error("Uploader: Invalid content hash in upload record", "hash", upload.ContentHash, "account_id", upload.AccountID)
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			logger.Error("Uploader: CRITICAL - Failed to mark upload attempt for invalid hash", "hash", upload.ContentHash, "account_id", upload.AccountID, "error", err)
		}
		return
	}

	logger.Info("Uploader: Uploading hash", "hash", upload.ContentHash, "account", upload.AccountID)

	// Check for context cancellation early
	select {
	case <-ctx.Done():
		logger.Info("Uploader: Request aborted during upload", "hash", upload.ContentHash)
		return
	default:
	}

	// Get primary address to construct S3 path
	address, err := w.rdb.GetPrimaryEmailForAccountWithRetry(ctx, upload.AccountID)
	if err != nil {
		logger.Error("Uploader: Failed to get primary address for account", "account_id", upload.AccountID, "error", err)
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			logger.Error("Uploader: CRITICAL - Failed to mark upload attempt after email lookup failure", "hash", upload.ContentHash, "account_id", upload.AccountID, "error", err)
		}
		return
	}

	s3Key := helpers.NewS3Key(address.Domain(), address.LocalPart(), upload.ContentHash)

	filePath := w.FilePath(upload.ContentHash, upload.AccountID)

	// Check if this content hash is already marked as uploaded by another worker for this user
	isUploaded, err := w.rdb.IsContentHashUploadedWithRetry(ctx, upload.ContentHash, upload.AccountID)
	if err != nil {
		logger.Error("Uploader: Failed to check if content hash is already uploaded", "hash", upload.ContentHash, "account_id", upload.AccountID, "error", err)
		// Mark attempt and let it be retried
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			logger.Error("Uploader: CRITICAL - Failed to mark upload attempt after upload check failure", "hash", upload.ContentHash, "account_id", upload.AccountID, "error", err)
		}
		return
	}

	if isUploaded {
		logger.Info("Uploader: Content hash already uploaded - skipping S3 upload", "hash", upload.ContentHash, "account", upload.AccountID)
		// Content is already in S3. Mark this specific message instance as uploaded
		// and delete the pending upload record.
		err := w.rdb.CompleteS3UploadWithRetry(ctx, upload.ContentHash, upload.AccountID)
		if err != nil {
			logger.Warn("Uploader: Failed to finalize S3 upload - keeping local file for retry", "hash", upload.ContentHash, "account", upload.AccountID, "error", err)
			return
		}
		// Only delete after successful DB update
		logger.Info("Uploader: Upload completed (already uploaded hash)", "hash", upload.ContentHash, "account", upload.AccountID)

		// The local file is unique to this upload task, so it can be safely removed.
		if err := w.RemoveLocalFile(filePath); err != nil {
			// Log is inside RemoveLocalFile
		}
		return // Done with this upload record
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			logger.Error("Uploader: CRITICAL - Failed to mark upload attempt after file read failure", "hash", upload.ContentHash, "account_id", upload.AccountID, "error", err)
		}
		logger.Error("Uploader: Could not read file", "path", filePath, "account_id", upload.AccountID, "error", err)
		return // Cannot proceed without the file
	}

	// Attempt to upload to S3 using resilient wrapper with circuit breakers and retries.
	// The storage layer should handle checking for existence.
	start := time.Now()
	err = w.s3.PutWithRetry(ctx, s3Key, bytes.NewReader(data), upload.Size)
	if err != nil {
		// Only count toward max_attempts for permanent errors (e.g., invalid data).
		// Transient S3 errors (network, timeout, circuit breaker) should NOT count,
		// because the upload will succeed once S3 recovers. This prevents message loss
		// from CleanupFailedUploads running after max_attempts is exhausted during
		// a prolonged S3 outage.
		if !w.isTransientS3Error(err) {
			if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
				logger.Error("Uploader: CRITICAL - Failed to mark upload attempt after S3 failure", "hash", upload.ContentHash, "account_id", upload.AccountID, "error", err)
			}
		} else {
			logger.Warn("Uploader: Transient S3 error — NOT counting toward max_attempts", "hash", upload.ContentHash, "account_id", upload.AccountID)
		}
		logger.Error("Uploader: Upload failed", "hash", upload.ContentHash, "account_id", upload.AccountID, "key", s3Key, "error", err)

		// Track upload failure
		metrics.UploadWorkerJobs.WithLabelValues("failure").Inc()
		metrics.S3UploadAttempts.WithLabelValues("failure").Inc()
		metrics.UploadWorkerDuration.Observe(time.Since(start).Seconds())
		return
	}

	// Finalize the upload in the database. This is a transactional operation.
	// It's critical to do this *before* removing the local source file.
	err = w.rdb.CompleteS3UploadWithRetry(ctx, upload.ContentHash, upload.AccountID)
	if err != nil {
		// If this fails, the S3 object might be orphaned temporarily, but the task is not lost.
		// The task will be retried after the lease expires. Because the local file still
		// exists, the retry can succeed.
		logger.Error("Uploader: CRITICAL - Failed to finalize DB after S3 upload - will retry", "hash", upload.ContentHash, "account_id", upload.AccountID, "error", err)
		return
	}

	// Move the uploaded file to the global cache. If the move fails (e.g., file
	// already in cache from another user's upload), delete the local file.
	if err := w.cache.MoveIn(filePath, upload.ContentHash); err != nil {
		logger.Error("Uploader: Failed to move uploaded hash to cache - deleting local file", "hash", upload.ContentHash, "error", err)
		if removeErr := w.RemoveLocalFile(filePath); removeErr != nil {
			// Log is inside RemoveLocalFile
		}
	} else {
		logger.Info("Uploader: Moved hash to cache after upload", "hash", upload.ContentHash)
	}

	// Track successful upload
	metrics.UploadWorkerJobs.WithLabelValues("success").Inc()
	metrics.S3UploadAttempts.WithLabelValues("success").Inc()
	metrics.UploadWorkerDuration.Observe(time.Since(start).Seconds())

	logger.Info("Uploader: Upload completed", "hash", upload.ContentHash, "account", upload.AccountID)
}

// reportError sends an error to the error channel if configured, otherwise logs it
func (w *UploadWorker) reportError(err error) {
	if w.errCh != nil {
		select {
		case w.errCh <- err:
		default:
			logger.Error("Uploader: Worker error (no listener)", "error", err)
		}
	} else {
		logger.Error("Uploader: Worker error", "error", err)
	}
}

func (w *UploadWorker) FilePath(contentHash string, accountID int64) string {
	// Validate content hash to prevent path traversal attacks
	if !isValidContentHash(contentHash) {
		logger.Warn("Uploader: Invalid content hash attempted", "hash", contentHash)
		// Return a safe fallback path that will fail cleanly
		return filepath.Join(w.path, "invalid", "invalid")
	}
	// Scope the local file by account ID to prevent conflicts and simplify cleanup.
	return filepath.Join(w.path, fmt.Sprintf("%d", accountID), contentHash)
}

// isValidContentHash validates that a content hash contains only safe characters
// and is the expected length for BLAKE3 hashes (64 hex characters)
func isValidContentHash(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	// Check that all characters are valid hex digits
	for _, r := range hash {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func (w *UploadWorker) StoreLocally(contentHash string, accountID int64, data []byte) (*string, error) {
	path := w.FilePath(contentHash, accountID)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write file with fsync to ensure durability before the DB transaction commits.
	// Without fsync, a crash could leave the DB referencing a file that never made it to disk.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create file %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path) // Clean up partial write
		return nil, fmt.Errorf("failed to write file %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to fsync file %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("failed to close file %s: %w", path, err)
	}

	// Fsync the parent directory to ensure the directory entry is durable.
	if err := syncDir(dir); err != nil {
		logger.Warn("Uploader: Failed to fsync directory (non-fatal)", "dir", dir, "error", err)
		// Non-fatal: the file data is already synced, directory entry may survive without this
	}

	return &path, nil
}

// syncDir fsyncs a directory to ensure new file entries are durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// isTransientS3Error checks if an S3 error is transient (network/timeout/circuit breaker)
// and should NOT count toward max_attempts. Only permanent errors should exhaust attempts.
func (w *UploadWorker) isTransientS3Error(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	transientPatterns := []string{
		"connection refused", "connection reset", "connection timeout",
		"i/o timeout", "network unreachable", "no such host",
		"temporary failure", "service unavailable", "internal server error",
		"bad gateway", "gateway timeout", "timeout", "slowdown",
		"throttling", "rate limit", "circuit breaker",
	}
	for _, pattern := range transientPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	return false
}

func (w *UploadWorker) RemoveLocalFile(path string) error {
	if err := os.Remove(path); err != nil {
		logger.Warn("Uploader: Uploaded but could not delete file", "path", path, "error", err)
	} else {
		stopAt, _ := filepath.Abs(w.path)
		removeEmptyParents(path, stopAt)
	}
	return nil
}

// monitorStuckUploads checks for uploads that have exceeded max attempts and logs warnings.
// This provides visibility into failed uploads that need manual intervention.
func (w *UploadWorker) monitorStuckUploads(ctx context.Context) error {
	stats, err := w.rdb.GetUploaderStatsWithRetry(ctx, w.maxAttempts)
	if err != nil {
		return fmt.Errorf("failed to get uploader stats: %w", err)
	}

	// Update Prometheus metrics
	metrics.QueueDepth.WithLabelValues("s3_upload_pending").Set(float64(stats.TotalPending))
	metrics.QueueDepth.WithLabelValues("s3_upload_failed").Set(float64(stats.FailedUploads))

	// Log summary
	if stats.TotalPending > 0 || stats.FailedUploads > 0 {
		logger.Info("UploaderMonitor: Queue status", "pending", stats.TotalPending,
			"pending_bytes", stats.TotalPendingSize, "failed", stats.FailedUploads)
	}

	// Alert if failed uploads exist
	if stats.FailedUploads > 0 {
		logger.Warn("UploaderMonitor: ALERT - uploads have failed and need attention", "count", stats.FailedUploads, "max_attempts", w.maxAttempts)

		// Get details of failed uploads
		failed, err := w.rdb.GetFailedUploadsWithRetry(ctx, w.maxAttempts, 10)
		if err != nil {
			logger.Error("UploaderMonitor: Failed to get failed upload details", "error", err)
		} else {
			for _, upload := range failed {
				logger.Warn("UploaderMonitor: Stuck upload", "id", upload.ID, "account", upload.AccountID, "hash", upload.ContentHash[:16], "attempts", upload.Attempts, "age", time.Since(upload.CreatedAt).Round(time.Minute))
			}
		}
	}

	return nil
}

func removeEmptyParents(path, stopAt string) {
	for {
		parent := filepath.Dir(path)
		if parent == stopAt || parent == "." || parent == "/" {
			break
		}
		// Try removing the parent directory
		err := os.Remove(parent)
		if err != nil {
			// Stop if not empty or permission denied
			break
		}
		path = parent
	}
}

// cleanupOrphanedFiles removes local files that no longer have a corresponding pending upload record.
// This handles cases where:
// - System crashes before pending upload was created
// - Partial file writes that were never completed
// - Race conditions during concurrent operations
// - Files left behind from failed operations
//
// The cleanup is conservative and only removes files older than a grace period to avoid
// deleting files that are currently being written or have very recent pending uploads.
func (w *UploadWorker) cleanupOrphanedFiles(ctx context.Context) error {
	start := time.Now()

	// Grace period before considering a file orphaned (10 minutes)
	// This ensures we don't delete files that are actively being processed
	gracePeriod := 10 * time.Minute
	cutoffTime := time.Now().Add(-gracePeriod)

	var filesChecked, filesRemoved int64
	var totalSize int64

	// Walk the upload directory tree
	err := filepath.Walk(w.path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Warn("UploaderCleanup: Error accessing path", "path", path, "error", err)
			return nil // Continue walking despite errors
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip recently created/modified files (within grace period)
		if info.ModTime().After(cutoffTime) {
			return nil
		}

		filesChecked++

		// Extract account ID and content hash from path
		// Path structure: /path/to/uploads/{accountID}/{contentHash}
		relPath, err := filepath.Rel(w.path, path)
		if err != nil {
			logger.Warn("UploaderCleanup: Failed to get relative path", "path", path, "error", err)
			return nil
		}

		// Parse path components
		parts := filepath.SplitList(relPath)
		if len(parts) < 2 {
			// Try with separator
			parts = strings.Split(relPath, string(filepath.Separator))
		}

		if len(parts) < 2 {
			logger.Warn("UploaderCleanup: Unexpected path structure", "path", relPath)
			return nil
		}

		// Get account ID and content hash
		accountIDStr := parts[0]
		contentHash := parts[len(parts)-1] // Last component is the hash

		// Parse account ID
		var accountID int64
		if _, err := fmt.Sscanf(accountIDStr, "%d", &accountID); err != nil {
			logger.Warn("UploaderCleanup: Invalid account ID in path", "path", path, "error", err)
			return nil
		}

		// Validate content hash
		if !isValidContentHash(contentHash) {
			logger.Warn("UploaderCleanup: Invalid content hash in path", "path", path)
			// Remove invalid files
			if removeErr := os.Remove(path); removeErr != nil {
				logger.Warn("UploaderCleanup: Failed to remove invalid file", "path", path, "error", removeErr)
			} else {
				filesRemoved++
				totalSize += info.Size()
				logger.Info("UploaderCleanup: Removed invalid file", "path", path)
			}
			return nil
		}

		// Check if pending upload exists in database
		exists, err := w.rdb.PendingUploadExistsWithRetry(ctx, contentHash, accountID)
		if err != nil {
			logger.Warn("UploaderCleanup: Failed to check pending upload", "hash", contentHash, "account", accountID, "error", err)
			return nil // Don't delete if we can't verify
		}

		if !exists {
			// File is orphaned - no pending upload record exists
			if removeErr := os.Remove(path); removeErr != nil {
				logger.Warn("UploaderCleanup: Failed to remove orphaned file", "path", path, "error", removeErr)
			} else {
				filesRemoved++
				totalSize += info.Size()
				logger.Info("UploaderCleanup: Removed orphaned file", "hash", contentHash, "account", accountID, "size", info.Size())

				// Try to remove empty parent directories
				stopAt, _ := filepath.Abs(w.path)
				removeEmptyParents(path, stopAt)
			}
		}

		return nil
	})

	duration := time.Since(start)

	if err != nil && err != context.Canceled {
		logger.Error("UploaderCleanup: Walk error", "error", err)
		return err
	}

	// Log cleanup summary
	logger.Info("UploaderCleanup: Completed", "duration", duration,
		"checked", filesChecked, "removed", filesRemoved, "bytes_freed", totalSize)

	// Track metrics
	metrics.UploadWorkerJobs.WithLabelValues("cleanup").Add(float64(filesRemoved))

	return nil
}
