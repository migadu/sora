package uploader

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
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
	errCh         chan<- error
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
	}, nil
}

func (w *UploadWorker) Start(ctx context.Context) {
	log.Println("[UPLOADER] starting worker")

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("[UPLOADER] worker stopped")
				return
			case <-ticker.C:
				log.Println("[UPLOADER] timer tick")
				if err := w.processPendingUploads(ctx); err != nil {
					select {
					case w.errCh <- err:
					default:
						log.Printf("[UPLOADER] worker error (no listener): %v", err)
					}
				}
			case <-w.notifyCh:
				log.Println("[UPLOADER] worker notified")
				_ = w.processPendingUploads(ctx)
			}
		}
	}()
}

func (w *UploadWorker) NotifyUploadQueued() {
	select {
	case w.notifyCh <- struct{}{}:
	default:
		// Don't block if notifyCh already has a signal
	}
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
				log.Printf("[UPLOADER] skipping upload for hash %s (ID %d) due to excessive failed attempts (%d)", upload.ContentHash, upload.ID, upload.Attempts)
				continue // Skip this upload and move to the next one in the batch
			}

			select {
			case <-ctx.Done():
				log.Println("[UPLOADER] context cancelled")
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
		log.Printf("[UPLOADER] ERROR: invalid content hash in upload record: %s", upload.ContentHash)
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			log.Printf("[UPLOADER] CRITICAL: failed to mark upload attempt for invalid hash %s: %v", upload.ContentHash, err)
		}
		return
	}

	log.Printf("[UPLOADER] uploading hash %s for account %d", upload.ContentHash, upload.AccountID)

	// Check for context cancellation early
	select {
	case <-ctx.Done():
		log.Printf("[UPLOADER] context cancelled during upload of hash %s", upload.ContentHash)
		return
	default:
	}

	// Get primary address to construct S3 path
	address, err := w.rdb.GetPrimaryEmailForAccountWithRetry(ctx, upload.AccountID)
	if err != nil {
		log.Printf("[UPLOADER] failed to get primary address for account %d: %v", upload.AccountID, err)
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			log.Printf("[UPLOADER] CRITICAL: failed to mark upload attempt for hash %s after email lookup failure: %v", upload.ContentHash, err)
		}
		return
	}

	s3Key := helpers.NewS3Key(address.Domain(), address.LocalPart(), upload.ContentHash)

	filePath := w.FilePath(upload.ContentHash, upload.AccountID)

	// Check if this content hash is already marked as uploaded by another worker for this user
	isUploaded, err := w.rdb.IsContentHashUploadedWithRetry(ctx, upload.ContentHash, upload.AccountID)
	if err != nil {
		log.Printf("[UPLOADER] failed to check if content hash %s is already uploaded for account %d: %v", upload.ContentHash, upload.AccountID, err)
		// Mark attempt and let it be retried
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			log.Printf("[UPLOADER] CRITICAL: failed to mark upload attempt for hash %s after upload check failure: %v", upload.ContentHash, err)
		}
		return
	}

	if isUploaded {
		log.Printf("[UPLOADER] content hash %s already uploaded for account %d, skipping S3 upload", upload.ContentHash, upload.AccountID)
		// Content is already in S3. Mark this specific message instance as uploaded
		// and delete the pending upload record.
		if err := w.rdb.CompleteS3UploadWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			log.Printf("[UPLOADER] WARNING: failed to finalize S3 upload for hash %s, account %d: %v", upload.ContentHash, upload.AccountID, err)
		} else {
			log.Printf("[UPLOADER] upload completed (already uploaded hash) for hash %s, account %d", upload.ContentHash, upload.AccountID)
		}
		// The local file is unique to this upload task, so it can be safely removed.
		if err := w.RemoveLocalFile(filePath); err != nil {
			// Log is inside RemoveLocalFile
		}
		return // Done with this upload record
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			log.Printf("[UPLOADER] CRITICAL: failed to mark upload attempt for hash %s after file read failure: %v", upload.ContentHash, err)
		}
		log.Printf("[UPLOADER] could not read file %s: %v", filePath, err)
		return // Cannot proceed without the file
	}

	// Attempt to upload to S3 using resilient wrapper with circuit breakers and retries.
	// The storage layer should handle checking for existence.
	start := time.Now()
	err = w.s3.PutWithRetry(ctx, s3Key, bytes.NewReader(data), upload.Size)
	if err != nil {
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			log.Printf("[UPLOADER] CRITICAL: failed to mark upload attempt for hash %s after S3 failure: %v", upload.ContentHash, err)
		}
		log.Printf("[UPLOADER] upload failed for %s (key: %s): %v", upload.ContentHash, s3Key, err)

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
		log.Printf("[UPLOADER] CRITICAL: failed to finalize DB after S3 upload for hash %s, account %d: %v. Will retry.", upload.ContentHash, upload.AccountID, err)
		return
	}

	// Move the uploaded file to the global cache. If the move fails (e.g., file
	// already in cache from another user's upload), delete the local file.
	if err := w.cache.MoveIn(filePath, upload.ContentHash); err != nil {
		log.Printf("[UPLOADER] failed to move uploaded hash %s to cache: %v. Deleting local file.", upload.ContentHash, err)
		if removeErr := w.RemoveLocalFile(filePath); removeErr != nil {
			// Log is inside RemoveLocalFile
		}
	} else {
		log.Printf("[UPLOADER] moved hash %s to cache after upload", upload.ContentHash)
	}

	// Track successful upload
	metrics.UploadWorkerJobs.WithLabelValues("success").Inc()
	metrics.S3UploadAttempts.WithLabelValues("success").Inc()
	metrics.UploadWorkerDuration.Observe(time.Since(start).Seconds())

	log.Printf("[UPLOADER] upload completed for hash %s, account %d", upload.ContentHash, upload.AccountID)
}

func (w *UploadWorker) FilePath(contentHash string, accountID int64) string {
	// Validate content hash to prevent path traversal attacks
	if !isValidContentHash(contentHash) {
		log.Printf("[UPLOADER] WARNING: invalid content hash attempted: %s", contentHash)
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
		log.Printf("[UPLOADER] WARNING: uploaded but could not delete file %s: %v", path, err)
	} else {
		stopAt, _ := filepath.Abs(w.path)
		removeEmptyParents(path, stopAt)
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
