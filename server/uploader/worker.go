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

	logger.Info("[UPLOADER] worker started")
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

	logger.Info("[UPLOADER] worker processing every 30s, cleanup and monitoring every 5min")

	// Process immediately on start
	w.processQueue(ctx)

	for {
		select {
		case <-ctx.Done():
			logger.Info("[UPLOADER] worker stopped due to context cancellation")
			return
		case <-w.stopCh:
			logger.Info("[UPLOADER] worker stopped due to stop signal")
			return
		case <-ticker.C:
			logger.Info("[UPLOADER] timer tick")
			if err := w.processQueue(ctx); err != nil {
				w.reportError(err)
			}
		case <-monitorTicker.C:
			logger.Info("[UPLOADER] monitor tick")
			if err := w.monitorStuckUploads(ctx); err != nil {
				logger.Errorf("[UPLOADER] monitor error: %v", err)
			}
		case <-cleanupTicker.C:
			logger.Info("[UPLOADER] cleanup tick")
			if err := w.cleanupOrphanedFiles(ctx); err != nil {
				logger.Errorf("[UPLOADER] cleanup error: %v", err)
			}
		case <-w.notifyCh:
			logger.Info("[UPLOADER] worker notified")
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

	logger.Info("[UPLOADER] worker stopped")
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
				logger.Infof("[UPLOADER] skipping upload for hash %s (ID %d) due to excessive failed attempts (%d)", upload.ContentHash, upload.ID, upload.Attempts)
				continue // Skip this upload and move to the next one in the batch
			}

			select {
			case <-ctx.Done():
				logger.Info("[UPLOADER] request aborted, waiting for in-flight uploads")
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
		logger.Errorf("[UPLOADER] invalid content hash in upload record: %s (account %d)", upload.ContentHash, upload.AccountID)
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			logger.Errorf("[UPLOADER] CRITICAL: failed to mark upload attempt for invalid hash %s (account %d): %v", upload.ContentHash, upload.AccountID, err)
		}
		return
	}

	logger.Infof("[UPLOADER] uploading hash %s for account %d", upload.ContentHash, upload.AccountID)

	// Check for context cancellation early
	select {
	case <-ctx.Done():
		logger.Infof("[UPLOADER] request aborted during upload of hash %s", upload.ContentHash)
		return
	default:
	}

	// Get primary address to construct S3 path
	address, err := w.rdb.GetPrimaryEmailForAccountWithRetry(ctx, upload.AccountID)
	if err != nil {
		logger.Errorf("[UPLOADER] failed to get primary address for account %d: %v", upload.AccountID, err)
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			logger.Errorf("[UPLOADER] CRITICAL: failed to mark upload attempt for hash %s (account %d) after email lookup failure: %v", upload.ContentHash, upload.AccountID, err)
		}
		return
	}

	s3Key := helpers.NewS3Key(address.Domain(), address.LocalPart(), upload.ContentHash)

	filePath := w.FilePath(upload.ContentHash, upload.AccountID)

	// Check if this content hash is already marked as uploaded by another worker for this user
	isUploaded, err := w.rdb.IsContentHashUploadedWithRetry(ctx, upload.ContentHash, upload.AccountID)
	if err != nil {
		logger.Errorf("[UPLOADER] failed to check if content hash %s is already uploaded for account %d: %v", upload.ContentHash, upload.AccountID, err)
		// Mark attempt and let it be retried
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			logger.Errorf("[UPLOADER] CRITICAL: failed to mark upload attempt for hash %s (account %d) after upload check failure: %v", upload.ContentHash, upload.AccountID, err)
		}
		return
	}

	if isUploaded {
		logger.Infof("[UPLOADER] content hash %s already uploaded for account %d, skipping S3 upload", upload.ContentHash, upload.AccountID)
		// Content is already in S3. Mark this specific message instance as uploaded
		// and delete the pending upload record.
		err := w.rdb.CompleteS3UploadWithRetry(ctx, upload.ContentHash, upload.AccountID)
		if err != nil {
			logger.Warnf("[UPLOADER] failed to finalize S3 upload for hash %s, account %d: %v - Keeping local file for retry.", upload.ContentHash, upload.AccountID, err)
			return
		}
		// Only delete after successful DB update
		logger.Infof("[UPLOADER] upload completed (already uploaded hash) for hash %s, account %d", upload.ContentHash, upload.AccountID)

		// The local file is unique to this upload task, so it can be safely removed.
		if err := w.RemoveLocalFile(filePath); err != nil {
			// Log is inside RemoveLocalFile
		}
		return // Done with this upload record
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			logger.Errorf("[UPLOADER] CRITICAL: failed to mark upload attempt for hash %s (account %d) after file read failure: %v", upload.ContentHash, upload.AccountID, err)
		}
		logger.Errorf("[UPLOADER] could not read file %s (account %d): %v", filePath, upload.AccountID, err)
		return // Cannot proceed without the file
	}

	// Attempt to upload to S3 using resilient wrapper with circuit breakers and retries.
	// The storage layer should handle checking for existence.
	start := time.Now()
	err = w.s3.PutWithRetry(ctx, s3Key, bytes.NewReader(data), upload.Size)
	if err != nil {
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			logger.Errorf("[UPLOADER] CRITICAL: failed to mark upload attempt for hash %s (account %d) after S3 failure: %v", upload.ContentHash, upload.AccountID, err)
		}
		logger.Errorf("[UPLOADER] upload failed for %s (account %d, key: %s): %v", upload.ContentHash, upload.AccountID, s3Key, err)

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
		logger.Errorf("[UPLOADER] CRITICAL: failed to finalize DB after S3 upload for hash %s, account %d: %v. Will retry.", upload.ContentHash, upload.AccountID, err)
		return
	}

	// Move the uploaded file to the global cache. If the move fails (e.g., file
	// already in cache from another user's upload), delete the local file.
	if err := w.cache.MoveIn(filePath, upload.ContentHash); err != nil {
		logger.Errorf("[UPLOADER] failed to move uploaded hash %s to cache: %v. Deleting local file.", upload.ContentHash, err)
		if removeErr := w.RemoveLocalFile(filePath); removeErr != nil {
			// Log is inside RemoveLocalFile
		}
	} else {
		logger.Infof("[UPLOADER] moved hash %s to cache after upload", upload.ContentHash)
	}

	// Track successful upload
	metrics.UploadWorkerJobs.WithLabelValues("success").Inc()
	metrics.S3UploadAttempts.WithLabelValues("success").Inc()
	metrics.UploadWorkerDuration.Observe(time.Since(start).Seconds())

	logger.Infof("[UPLOADER] upload completed for hash %s, account %d", upload.ContentHash, upload.AccountID)
}

// reportError sends an error to the error channel if configured, otherwise logs it
func (w *UploadWorker) reportError(err error) {
	if w.errCh != nil {
		select {
		case w.errCh <- err:
		default:
			logger.Errorf("[UPLOADER] worker error (no listener): %v", err)
		}
	} else {
		logger.Errorf("[UPLOADER] worker error: %v", err)
	}
}

func (w *UploadWorker) FilePath(contentHash string, accountID int64) string {
	// Validate content hash to prevent path traversal attacks
	if !isValidContentHash(contentHash) {
		logger.Warnf("[UPLOADER] invalid content hash attempted: %s", contentHash)
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
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write file %s: %w", path, err)
	}
	return &path, nil
}

func (w *UploadWorker) RemoveLocalFile(path string) error {
	if err := os.Remove(path); err != nil {
		logger.Warnf("[UPLOADER] uploaded but could not delete file %s: %v", path, err)
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
		logger.Infof("[UPLOADER-MONITOR] Queue: %d pending (%d bytes), %d failed (max attempts reached)",
			stats.TotalPending, stats.TotalPendingSize, stats.FailedUploads)
	}

	// Alert if failed uploads exist
	if stats.FailedUploads > 0 {
		logger.Warnf("[UPLOADER-MONITOR] ALERT: %d uploads have failed after %d attempts and need attention",
			stats.FailedUploads, w.maxAttempts)

		// Get details of failed uploads
		failed, err := w.rdb.GetFailedUploadsWithRetry(ctx, w.maxAttempts, 10)
		if err != nil {
			logger.Errorf("[UPLOADER-MONITOR] failed to get failed upload details: %v", err)
		} else {
			for _, upload := range failed {
				logger.Warnf("[UPLOADER-MONITOR] Stuck upload: ID=%d Account=%d Hash=%s Attempts=%d Age=%s",
					upload.ID, upload.AccountID, upload.ContentHash[:16], upload.Attempts,
					time.Since(upload.CreatedAt).Round(time.Minute))
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
			logger.Warnf("[UPLOADER-CLEANUP] error accessing path %s: %v", path, err)
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
			logger.Warnf("[UPLOADER-CLEANUP] failed to get relative path for %s: %v", path, err)
			return nil
		}

		// Parse path components
		parts := filepath.SplitList(relPath)
		if len(parts) < 2 {
			// Try with separator
			parts = strings.Split(relPath, string(filepath.Separator))
		}

		if len(parts) < 2 {
			logger.Warnf("[UPLOADER-CLEANUP] unexpected path structure: %s", relPath)
			return nil
		}

		// Get account ID and content hash
		accountIDStr := parts[0]
		contentHash := parts[len(parts)-1] // Last component is the hash

		// Parse account ID
		var accountID int64
		if _, err := fmt.Sscanf(accountIDStr, "%d", &accountID); err != nil {
			logger.Warnf("[UPLOADER-CLEANUP] invalid account ID in path %s: %v", path, err)
			return nil
		}

		// Validate content hash
		if !isValidContentHash(contentHash) {
			logger.Warnf("[UPLOADER-CLEANUP] invalid content hash in path %s", path)
			// Remove invalid files
			if removeErr := os.Remove(path); removeErr != nil {
				logger.Warnf("[UPLOADER-CLEANUP] failed to remove invalid file %s: %v", path, removeErr)
			} else {
				filesRemoved++
				totalSize += info.Size()
				logger.Infof("[UPLOADER-CLEANUP] removed invalid file %s", path)
			}
			return nil
		}

		// Check if pending upload exists in database
		exists, err := w.rdb.PendingUploadExistsWithRetry(ctx, contentHash, accountID)
		if err != nil {
			logger.Warnf("[UPLOADER-CLEANUP] failed to check pending upload for %s (account %d): %v", contentHash, accountID, err)
			return nil // Don't delete if we can't verify
		}

		if !exists {
			// File is orphaned - no pending upload record exists
			if removeErr := os.Remove(path); removeErr != nil {
				logger.Warnf("[UPLOADER-CLEANUP] failed to remove orphaned file %s: %v", path, removeErr)
			} else {
				filesRemoved++
				totalSize += info.Size()
				logger.Infof("[UPLOADER-CLEANUP] removed orphaned file %s (account %d, size %d bytes)", contentHash, accountID, info.Size())

				// Try to remove empty parent directories
				stopAt, _ := filepath.Abs(w.path)
				removeEmptyParents(path, stopAt)
			}
		}

		return nil
	})

	duration := time.Since(start)

	if err != nil && err != context.Canceled {
		logger.Errorf("[UPLOADER-CLEANUP] walk error: %v", err)
		return err
	}

	// Log cleanup summary
	logger.Infof("[UPLOADER-CLEANUP] completed in %v: checked %d files, removed %d orphaned files (%d bytes freed)",
		duration, filesChecked, filesRemoved, totalSize)

	// Track metrics
	metrics.UploadWorkerJobs.WithLabelValues("cleanup").Add(float64(filesRemoved))

	return nil
}
