package uploader

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/migadu/sora/pkg/resilient"
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
	// ExhaustUploadAttemptsWithRetry immediately sets attempts = maxAttempts for a
	// permanently-lost upload (file missing AND not in S3) so it moves to the failed
	// list without cycling through every remaining retry slot.
	ExhaustUploadAttemptsWithRetry(ctx context.Context, contentHash string, accountID int64, maxAttempts int) error
	// PendingUploadKeys returns the S3 keys that still have to be written before the
	// account's message rows for this content hash may be marked uploaded.
	PendingUploadKeys(ctx context.Context, contentHash string, accountID int64) ([]string, error)
	ExecuteWithS3ObjectSessionLock(ctx context.Context, contentHash string, accountID int64, executionFunc func() error) error
	CompleteS3UploadWithRetry(ctx context.Context, contentHash string, accountID int64) error
	// ExistingPendingUploads returns the subset of contentHashes that still have a
	// pending_uploads row for the account. The cleanup scan asks per batch rather than
	// per file: the staging tree is largest during an S3 outage or a stranded backlog,
	// which is exactly when the database is already carrying the queue.
	ExistingPendingUploads(ctx context.Context, accountID int64, contentHashes []string) (map[string]struct{}, error)
	GetUploaderStatsWithRetry(ctx context.Context, maxAttempts int) (*db.UploaderStats, error)
	GetFailedUploadsWithRetry(ctx context.Context, maxAttempts int, limit int) ([]db.PendingUpload, error)
	// PendingUploadBacklog reports the retryable uploads this instance owns. Scoped to
	// the instance because a pending upload is leased only by its creator (the body is
	// a file on that node's disk), so this is the queue this worker alone can drain.
	PendingUploadBacklog(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error)
	// RecordInstanceHeartbeatWithRetry proves this instance still exists. Pending
	// uploads are leased only by their creating instance, so the cleaner reaps an
	// unfinished upload once its owner stops beating (db.CleanupFailedUploads).
	RecordInstanceHeartbeatWithRetry(ctx context.Context, instanceID string) error
}

// UploadBacklog is the state of one instance's retryable pending uploads, i.e. the
// ones still waiting for S3 rather than written off as failed.
type UploadBacklog struct {
	Count  int64
	Bytes  int64
	Oldest time.Time // zero when Count is 0
}

// resilientUploaderDB adapts the resilient database to UploaderDB, adding the
// batched orphan lookup the cleanup scan needs.
type resilientUploaderDB struct {
	*resilient.ResilientDatabase
}

// PendingUploadBacklog measures the queue this instance still has to write. Served by
// idx_pending_uploads_instance_id_created_at, so the MIN is an index lookup.
func (d resilientUploaderDB) PendingUploadBacklog(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
	var backlog UploadBacklog
	var oldest sql.NullTime
	err := d.QueryRowWithRetry(ctx, `
		SELECT COUNT(*), COALESCE(SUM(size), 0), MIN(created_at)
		FROM pending_uploads
		WHERE instance_id = $1 AND attempts < $2
	`, instanceID, maxAttempts).Scan(&backlog.Count, &backlog.Bytes, &oldest)
	if err != nil {
		return UploadBacklog{}, fmt.Errorf("failed to measure pending upload backlog of instance %s: %w", instanceID, err)
	}
	if oldest.Valid {
		backlog.Oldest = oldest.Time
	}
	return backlog, nil
}

func (d resilientUploaderDB) ExistingPendingUploads(ctx context.Context, accountID int64, contentHashes []string) (map[string]struct{}, error) {
	rows, err := d.QueryWithRetry(ctx, `
		SELECT content_hash FROM pending_uploads WHERE account_id = $1 AND content_hash = ANY($2)
	`, accountID, contentHashes)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending uploads for account %d: %w", accountID, err)
	}
	defer rows.Close()

	existing := make(map[string]struct{}, len(contentHashes))
	for rows.Next() {
		var contentHash string
		if err := rows.Scan(&contentHash); err != nil {
			return nil, fmt.Errorf("failed to scan pending upload hash: %w", err)
		}
		existing[contentHash] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to list pending uploads for account %d: %w", accountID, err)
	}
	return existing, nil
}

// PendingUploadKeys builds the keys from the s3_domain/s3_localpart recorded on each
// message row at insert time, which is what every reader uses to build its GET key.
// One (content_hash, account_id) pair can span several keys — the pair is unique in
// pending_uploads, while the rows behind it were keyed from whatever the account's
// primary address was when each was inserted — and CompleteS3Upload marks all of them
// uploaded, so each key that has no object yet must be written. A key is left out once
// a non-expunged row carries it as uploaded: its object is already in S3.
//
// Pinned to the master because the message rows and the pending_uploads row commit in
// one transaction: a lagging replica could answer "no keys", which the caller reads as
// "nothing left to write" and would finalize an upload that never happened.
func (d resilientUploaderDB) PendingUploadKeys(ctx context.Context, contentHash string, accountID int64) ([]string, error) {
	rows, err := d.QueryWithRetry(context.WithValue(ctx, consts.UseMasterDBKey, true), `
		SELECT s3_domain, s3_localpart FROM messages
		WHERE content_hash = $1 AND account_id = $2
		GROUP BY s3_domain, s3_localpart
		HAVING bool_or(NOT uploaded) AND NOT bool_or(uploaded AND expunged_at IS NULL)
	`, contentHash, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve storage keys for hash %s of account %d: %w", contentHash, accountID, err)
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var domain, localpart string
		if err := rows.Scan(&domain, &localpart); err != nil {
			return nil, fmt.Errorf("failed to scan storage key parts: %w", err)
		}
		keys = append(keys, helpers.NewS3Key(domain, localpart, contentHash))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to resolve storage keys for hash %s of account %d: %w", contentHash, accountID, err)
	}
	return keys, nil
}

// UploaderS3 defines the S3 storage operations needed by the uploader worker.
type UploaderS3 interface {
	PutWithRetry(ctx context.Context, key string, reader io.Reader, size int64) error
	// ExistsWithRetry checks whether an object already exists in S3.
	// Used to self-heal uploads whose local file is missing but whose content
	// was already stored in S3 by a prior attempt.
	ExistsWithRetry(ctx context.Context, key string) (bool, error)
}

// UploaderCache defines the cache operations needed by the uploader worker.
type UploaderCache interface {
	MoveIn(srcPath, contentHash string) error
}

type UploadWorker struct {
	cleanupGracePeriod time.Duration // set via SetCleanupGracePeriod; 0 → default 1h
	rdb                UploaderDB
	s3                 UploaderS3
	cache              UploaderCache
	path               string
	batchSize          int
	concurrency        int
	maxAttempts        int
	retryInterval      time.Duration
	instanceID         string
	notifyCh           chan struct{}
	stopCh             chan struct{}
	errCh              chan<- error
	wg                 sync.WaitGroup
	mu                 sync.Mutex
	running            bool
	// syncUpload enables synchronous upload mode for tests.  When true,
	// NotifyUploadQueued processes the queue in the caller's goroutine
	// instead of waking the background worker.  See EnableSyncUpload.
	syncUpload syncBool

	maxStagingSize     int64
	currentStagingSize int64 // Atomic tracker for the global staging queue size
	// lastStallReport is when the current stall episode was last reported, in Unix
	// nanoseconds; 0 means no episode is in progress. Atomic, like currentStagingSize.
	lastStallReport int64
}

// syncBool is a goroutine-safe boolean flag backed by a sync.Mutex.
// We avoid sync/atomic.Bool to prevent a formatter-induced import cycle:
// the goimports tool would silently drop "sync/atomic" if the build tag
// evaluation order is not what we expect.  A mutex-based flag is simpler
// and correct for this low-frequency use case.
type syncBool struct {
	mu  sync.Mutex
	val bool
}

func (b *syncBool) Store(v bool) {
	b.mu.Lock()
	b.val = v
	b.mu.Unlock()
}

func (b *syncBool) Load() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.val
}

func New(ctx context.Context, path string, batchSize int, concurrency int, maxAttempts int, retryInterval time.Duration, maxStagingSize int64, instanceID string, rdb *resilient.ResilientDatabase, s3 *storage.S3Storage, cache *cache.Cache, errCh chan<- error) (*UploadWorker, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, fmt.Errorf("failed to create local path %s: %w", path, err)
		}
	}
	// Wrap S3 storage with resilient patterns including circuit breakers
	resilientS3 := resilient.NewResilientS3Storage(s3)
	// Convert typed-nil *cache.Cache to a proper nil UploaderCache interface.
	// Without this, w.cache != nil is true for a (*cache.Cache)(nil) value,
	// causing a panic when MoveIn is called on the nil receiver.
	var uploaderCache UploaderCache
	if cache != nil {
		uploaderCache = cache
	}
	return newWithS3Interface(path, batchSize, concurrency, maxAttempts, retryInterval, maxStagingSize, instanceID, rdb, resilientS3, uploaderCache, errCh)
}

// NewWithS3Interface creates an UploadWorker with custom UploaderS3 and UploaderCache
// implementations.  This is intended for test environments where a no-op S3 and/or
// a no-op cache are needed.  The caller is responsible for any wrapping it requires.
func NewWithS3Interface(path string, batchSize int, concurrency int, maxAttempts int, retryInterval time.Duration, maxStagingSize int64, instanceID string, rdb *resilient.ResilientDatabase, s3 UploaderS3, uploaderCache UploaderCache, errCh chan<- error) (*UploadWorker, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0755); err != nil {
			return nil, fmt.Errorf("failed to create local path %s: %w", path, err)
		}
	}
	return newWithS3Interface(path, batchSize, concurrency, maxAttempts, retryInterval, maxStagingSize, instanceID, rdb, s3, uploaderCache, errCh)
}

func newWithS3Interface(path string, batchSize int, concurrency int, maxAttempts int, retryInterval time.Duration, maxStagingSize int64, instanceID string, rdb *resilient.ResilientDatabase, s3 UploaderS3, uploaderCache UploaderCache, errCh chan<- error) (*UploadWorker, error) {
	notifyCh := make(chan struct{}, 1)
	return &UploadWorker{
		rdb:            resilientUploaderDB{rdb},
		s3:             s3,
		cache:          uploaderCache,
		errCh:          errCh,
		path:           path,
		batchSize:      batchSize,
		concurrency:    concurrency,
		maxAttempts:    maxAttempts,
		retryInterval:  retryInterval,
		maxStagingSize: maxStagingSize,
		instanceID:     instanceID,
		notifyCh:       notifyCh,
		stopCh:         make(chan struct{}),
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

	heartbeatTicker := time.NewTicker(instanceHeartbeatInterval)
	defer heartbeatTicker.Stop()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	logger.Info("Uploader: worker processing every 10s, cleanup and monitoring every 5min")

	// Beat before the first upload: the spool files this instance is about to own
	// may only be reaped once it is known to have stopped beating.
	w.recordHeartbeat(ctx)

	// Learn the staging total before any delivery is admitted: it is cached in memory,
	// so after a restart the guard would otherwise report an empty spool until the
	// first monitor tick, whatever is already on disk.
	if err := w.monitorStuckUploads(ctx); err != nil {
		logger.Error("Uploader: Monitor error", "error", err)
	}

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
		case <-heartbeatTicker.C:
			w.recordHeartbeat(ctx)
		case <-w.notifyCh:
			logger.Info("Uploader: worker notified")
			_ = w.processQueue(ctx)
		}
	}
}

// instanceHeartbeatInterval is how often this instance proves it still exists.
// It must stay far below cleanup.instance_liveness_threshold so that a database
// hiccup, or a few missed beats, can never make a live instance look decommissioned
// and get its unuploaded messages reaped.
const instanceHeartbeatInterval = time.Minute

// recordHeartbeat publishes this instance's liveness. A failure is logged and
// otherwise ignored: the next beat overwrites it, and the cleaner only acts after
// instanceLiveness worth of consecutive silence.
func (w *UploadWorker) recordHeartbeat(ctx context.Context) {
	if err := w.rdb.RecordInstanceHeartbeatWithRetry(ctx, w.instanceID); err != nil {
		if ctx.Err() != nil {
			return // shutting down
		}
		logger.Warn("Uploader: Failed to record instance heartbeat", "instance_id", w.instanceID, "error", err)
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

// SetCleanupGracePeriod configures how old a local upload file must be before
// cleanupOrphanedFiles will consider removing it.  The value must be long enough
// to guarantee that any concurrent DB transaction (writing the pending_upload
// record) has committed before the cleanup consults the database.
//
// Set from cfg.Uploader.GetCleanupGracePeriod() at startup.
// If never called (or called with 0), the default of 1 hour is used.
func (w *UploadWorker) SetCleanupGracePeriod(d time.Duration) {
	w.cleanupGracePeriod = d
}

// EnableSyncUpload puts the worker into synchronous-upload mode.
// In this mode NotifyUploadQueued processes the pending-upload queue in the
// caller's goroutine before returning, so that by the time the caller
// (e.g. the IMAP APPEND handler) hands back the response, messages are
// already marked uploaded=true in the database.
//
// This is intended for test environments that use a no-op or instant S3
// implementation.  It must not be used in production.
func (w *UploadWorker) EnableSyncUpload() {
	w.syncUpload.Store(true)
}

func (w *UploadWorker) NotifyUploadQueued() {
	if w.syncUpload.Load() {
		// Synchronous mode (tests): process the queue inline so the caller
		// can safely FETCH the message immediately after APPEND.
		_ = w.processQueue(context.Background())
		return
	}
	select {
	case w.notifyCh <- struct{}{}:
	default:
		// Don't block if notifyCh already has a signal
	}
}

// DrainSync synchronously processes all currently pending uploads in the caller's
// goroutine and blocks until they are done.  It is intended for use in tests that
// need uploads to complete (and messages to be marked uploaded=true in the DB)
// before issuing a FETCH command.  It must not be called in production code paths.
func (w *UploadWorker) DrainSync(ctx context.Context) error {
	return w.processQueue(ctx)
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

	logger.Info("Uploader: Uploading hash", "hash", upload.ContentHash, "account_id", upload.AccountID)

	// The keys come from the message rows, not from the account's current primary
	// address: readers build their GET key from the s3_domain/s3_localpart each row
	// recorded at insert time, so a primary address changed while this upload sat in
	// the queue must not move the object.
	keys, err := w.rdb.PendingUploadKeys(ctx, upload.ContentHash, upload.AccountID)
	if err != nil {
		logger.Error("Uploader: Failed to resolve storage keys for upload", "hash", upload.ContentHash, "account_id", upload.AccountID, "error", err)
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			logger.Error("Uploader: CRITICAL - Failed to mark upload attempt after key lookup failure", "hash", upload.ContentHash, "account_id", upload.AccountID, "error", err)
		}
		return
	}

	filePath := w.FilePath(upload.ContentHash, upload.AccountID)

	if len(keys) == 0 {
		logger.Info("Uploader: Content hash already uploaded - skipping S3 upload", "hash", upload.ContentHash, "account_id", upload.AccountID)
		// Every key these rows point at already holds the content, so finalizing only
		// clears the leftover pending_uploads record.
		err := w.rdb.CompleteS3UploadWithRetry(ctx, upload.ContentHash, upload.AccountID)
		if err != nil {
			logger.Warn("Uploader: Failed to finalize S3 upload - keeping local file for retry", "hash", upload.ContentHash, "account_id", upload.AccountID, "error", err)
			return
		}
		// Only delete after successful DB update
		logger.Info("Uploader: Upload completed (already uploaded hash)", "hash", upload.ContentHash, "account_id", upload.AccountID)

		// The local file is unique to this upload task, so it can be safely removed.
		if err := w.RemoveLocalFile(filePath); err != nil {
			// Log is inside RemoveLocalFile
		}
		return // Done with this upload record
	}

	// Stream the body off the disk it already sits on rather than reading it whole:
	// `concurrency` uploads run at once, so a buffered body costs concurrency x message
	// size of RAM on exactly the nodes that are busiest. Nothing here needs the bytes
	// resident - the size guard stats, the S3 seam takes an io.Reader, and the cache
	// moves the file by path.
	file, err := os.Open(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			// Unexpected error (e.g. permissions) - not a missing-file situation.
			if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
				logger.Error("Uploader: CRITICAL - Failed to mark upload attempt after file read failure", "hash", upload.ContentHash, "account_id", upload.AccountID, "error", err)
			}
			logger.Error("Uploader: Could not read file", "path", filePath, "account_id", upload.AccountID, "error", err)
			return
		}

		// Local file is missing (ENOENT). This can happen when:
		//   a) cleanupOrphanedFiles deleted it just before the DB transaction committed
		//      (the race condition fixed by the 1-hour grace period - this path is now
		//       much rarer but still theoretically possible on very long transactions).
		//   b) The file was uploaded to S3 by a prior attempt, CompleteS3UploadWithRetry
		//      succeeded at marking messages uploaded but the pending_upload DELETE failed,
		//      leaving the record stuck; a subsequent run then deleted the local file.
		//
		// In case (b) - and whenever S3 already has the content for any reason - we can
		// self-heal by calling CompleteS3UploadWithRetry directly, without the local file.
		// This prevents CleanupFailedUploads from eventually deleting the user's messages
		// even though their content is safely stored in S3 (the [OK] EXISTS scenario).
		logger.Warn("Uploader: Local file missing -> checking S3 for existing content",
			"hash", upload.ContentHash, "account_id", upload.AccountID, "path", filePath)

		// Every key has to be there: finalizing marks all the rows behind this upload
		// uploaded, so one key still missing its object leaves those messages readable
		// as nothing at all, with no local copy left to write from.
		s3Exists := true
		for _, key := range keys {
			exists, statErr := w.s3.ExistsWithRetry(ctx, key)
			if statErr != nil {
				// S3 is unreachable - don't count as a permanent failure.
				logger.Warn("Uploader: Could not check S3 existence after missing file",
					"hash", upload.ContentHash, "account_id", upload.AccountID, "key", key, "error", statErr)
				// Do NOT increment attempts: the content may be in S3; we'll retry next cycle.
				return
			}
			if !exists {
				logger.Warn("Uploader: Local file missing and key absent from S3",
					"hash", upload.ContentHash, "account_id", upload.AccountID, "key", key)
				s3Exists = false
				break
			}
		}

		if s3Exists {
			// Content is already in S3. Complete the upload (mark messages as uploaded,
			// remove the pending_upload record) so the user's messages are accessible.
			logger.Info("Uploader: Local file missing but content found in S3 - self-healing upload",
				"hash", upload.ContentHash, "account_id", upload.AccountID)

			err = w.rdb.ExecuteWithS3ObjectSessionLock(ctx, upload.ContentHash, upload.AccountID, func() error {
				// Use detached background context during shutdown to ensure state consistency
				dbCtx := ctx
				if ctx.Err() != nil {
					var cancel context.CancelFunc
					dbCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					logger.Info("Uploader: Using background context for self-heal DB finalization during shutdown", "hash", upload.ContentHash)
				}

				return w.rdb.CompleteS3UploadWithRetry(dbCtx, upload.ContentHash, upload.AccountID)
			})

			if err != nil {
				logger.Error("Uploader: CRITICAL - Failed to complete upload after S3 existence recovery",
					"hash", upload.ContentHash, "account_id", upload.AccountID, "error", err)
				return // Retry next cycle; do NOT increment attempts
			}
			logger.Info("Uploader: Upload self-healed via S3 existence check",
				"hash", upload.ContentHash, "account_id", upload.AccountID)
			metrics.UploadWorkerJobs.WithLabelValues("success").Inc()
			return
		}

		// File is truly missing AND S3 doesn't have it - content is genuinely lost.
		// Immediately exhaust all remaining attempts so this record moves to the
		// "failed" list on the very next monitor tick, rather than cycling through
		// every remaining retry slot (up to maxAttempts × retryInterval wasted time
		// and S3 API calls).
		if exhaustErr := w.rdb.ExhaustUploadAttemptsWithRetry(ctx, upload.ContentHash, upload.AccountID, w.maxAttempts); exhaustErr != nil {
			logger.Error("Uploader: CRITICAL - Failed to exhaust upload attempts after missing file",
				"hash", upload.ContentHash, "account_id", upload.AccountID, "error", exhaustErr)
		}
		logger.Error("Uploader: Could not read file - content permanently lost, exhausted attempts",
			"path", filePath, "account_id", upload.AccountID, "error", err)
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		logger.Error("Uploader: Could not stat file", "path", filePath, "account_id", upload.AccountID, "error", err)
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			logger.Error("Uploader: CRITICAL - Failed to mark upload attempt after file stat failure", "hash", upload.ContentHash, "account_id", upload.AccountID, "error", err)
		}
		return
	}

	// Validate data integrity before uploading to S3.
	// The TOCTOU race that caused empty uploads has been fixed (file existence
	// check before StoreLocally), but this guard catches any other corruption
	// scenario (disk errors, unknown bugs) to prevent uploading garbage to S3
	// and marking the message as uploaded when the content is wrong.
	if info.Size() != upload.Size {
		logger.Error("Uploader: CRITICAL - File size mismatch, refusing to upload corrupted data",
			"hash", upload.ContentHash, "account_id", upload.AccountID,
			"file_size", info.Size(), "expected_size", upload.Size, "path", filePath)
		if err := w.rdb.MarkUploadAttemptWithRetry(ctx, upload.ContentHash, upload.AccountID); err != nil {
			logger.Error("Uploader: CRITICAL - Failed to mark upload attempt after size mismatch",
				"hash", upload.ContentHash, "account_id", upload.AccountID, "error", err)
		}
		metrics.UploadWorkerJobs.WithLabelValues("failure").Inc()
		return
	}

	// Attempt to upload to S3 using session-level advisory lock instead of transaction-level.
	// This ensures we do not execute long-running I/O within a single open Postgres transaction.
	start := time.Now()
	var shutdownRequested bool

	err = w.rdb.ExecuteWithS3ObjectSessionLock(ctx, upload.ContentHash, upload.AccountID, func() error {
		// Capture if shutdown is requested during our execution
		select {
		case <-ctx.Done():
			shutdownRequested = true
		default:
		}

		// Run S3 PUT, once per key the message rows point at. Every key gets the whole
		// body, so rewind between them: the resilient layer rewinds only around its own
		// retries of a single PUT.
		for _, key := range keys {
			if _, seekErr := file.Seek(0, io.SeekStart); seekErr != nil {
				return fmt.Errorf("failed to rewind %s for upload: %w", filePath, seekErr)
			}
			if s3Err := w.s3.PutWithRetry(ctx, key, file, upload.Size); s3Err != nil {
				return s3Err
			}
		}

		// Finalize the upload in the database.
		// It's critical to do this *before* removing the local source file.
		//
		// During shutdown, use a background context with a timeout to ensure the database
		// update completes even though the main context is canceled. This prevents the
		// "context canceled" error that leaves uploads in an inconsistent state (uploaded
		// to S3 but not marked complete in the database).
		dbCtx := ctx
		if shutdownRequested || ctx.Err() != nil {
			var cancel context.CancelFunc
			dbCtx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			logger.Info("Uploader: Using background context for DB finalization during shutdown", "hash", upload.ContentHash)
		}

		return w.rdb.CompleteS3UploadWithRetry(dbCtx, upload.ContentHash, upload.AccountID)
	})

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
			logger.Warn("Uploader: Transient error during S3 upload/DB finalization - NOT counting toward max_attempts", "hash", upload.ContentHash, "account_id", upload.AccountID)
		}
		logger.Error("Uploader: Upload or finalize failed", "hash", upload.ContentHash, "account_id", upload.AccountID, "keys", strings.Join(keys, " "), "error", err)

		// Track upload failure
		metrics.UploadWorkerJobs.WithLabelValues("failure").Inc()
		metrics.S3UploadAttempts.WithLabelValues("failure").Inc()
		metrics.UploadWorkerDuration.Observe(time.Since(start).Seconds())

		// IMPORTANT: We do not retry here, the retry loop will pick it up later from pending_uploads
		return
	}

	// Move the uploaded file to the global cache (if a cache is configured).
	// If the move fails, or no cache is present, delete the local file.
	if w.cache != nil {
		if err := w.cache.MoveIn(filePath, upload.ContentHash); err != nil {
			logger.Error("Uploader: Failed to move uploaded hash to cache - deleting local file", "hash", upload.ContentHash, "error", err)
			if removeErr := w.RemoveLocalFile(filePath); removeErr != nil {
				// Log is inside RemoveLocalFile
			}
		} else {
			w.addStagingSize(-upload.Size)
			logger.Info("Uploader: Moved hash to cache after upload", "hash", upload.ContentHash)
		}
	} else {
		// No cache configured — remove the local file after successful DB update.
		if removeErr := w.RemoveLocalFile(filePath); removeErr != nil {
			// Log is inside RemoveLocalFile
		}
	}

	// Track successful upload
	metrics.UploadWorkerJobs.WithLabelValues("success").Inc()
	metrics.S3UploadAttempts.WithLabelValues("success").Inc()
	metrics.UploadWorkerDuration.Observe(time.Since(start).Seconds())

	logger.Info("Uploader: Upload completed", "hash", upload.ContentHash, "account_id", upload.AccountID)
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

	// Bytes already accounted for at this path: an overwrite replaces them rather
	// than adding to the spool.
	previousSize := fileSize(path)

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

	w.addStagingSize(int64(len(data)) - previousSize)

	return &path, nil
}

// fileSize returns the size of a file, or 0 if it cannot be stat'ed.
func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
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

	// Check for known sentinel errors first (preferred method)
	if errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) ||
		errors.Is(err, circuitbreaker.ErrTooManyRequests) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, context.Canceled) ||
		errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, syscall.ECONNRESET) {
		return true
	}

	// Fallback to string matching for errors from external libraries (AWS SDK, network stack)
	// that don't expose typed errors
	errStr := strings.ToLower(err.Error())
	transientPatterns := []string{
		"connection refused", "connection reset", "connection timeout",
		"i/o timeout", "network unreachable", "no such host",
		"temporary failure", "service unavailable", "internal server error",
		"bad gateway", "gateway timeout", "timeout", "slowdown",
		"throttling", "rate limit", "closed network connection",
	}
	for _, pattern := range transientPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	return false
}

func (w *UploadWorker) RemoveLocalFile(path string) error {
	size := fileSize(path)
	if err := os.Remove(path); err != nil {
		logger.Warn("Uploader: Uploaded but could not delete file", "path", path, "error", err)
	} else {
		w.addStagingSize(-size)
		stopAt, _ := filepath.Abs(w.path)
		removeEmptyParents(path, stopAt)
	}
	return nil
}

// monitorStuckUploads checks for uploads that have exceeded max attempts and logs warnings.
// This provides visibility into failed uploads that need manual intervention.
func (w *UploadWorker) monitorStuckUploads(ctx context.Context) error {
	sizeBeforeQuery := atomic.LoadInt64(&w.currentStagingSize)

	stats, err := w.rdb.GetUploaderStatsWithRetry(ctx, w.maxAttempts)
	if err != nil {
		return fmt.Errorf("failed to get uploader stats: %w", err)
	}

	// Update Prometheus metrics
	metrics.QueueDepth.WithLabelValues("s3_upload_pending").Set(float64(stats.TotalPending))
	metrics.QueueDepth.WithLabelValues("s3_upload_failed").Set(float64(stats.FailedUploads))

	// Re-base the staging limit guard on THIS instance's staged bytes. stats is
	// cluster-wide (GetUploaderStats has no instance filter), and max_staging_size
	// guards this node's own staging directory: rebasing from the cluster total would
	// make one node's backlog reject deliveries on every node, however empty its disk.
	// Applied as a delta so that messages staged while the query was in flight - which
	// the snapshot predates - are not dropped from the count.
	backlog, backlogErr := w.rdb.PendingUploadBacklog(ctx, w.instanceID, w.maxAttempts)
	if backlogErr != nil {
		if ctx.Err() != nil {
			return nil // shutting down
		}
		// Leave the counter alone rather than rebasing from a number that is not ours.
		logger.Error("UploaderMonitor: Failed to measure pending upload backlog", "instance_id", w.instanceID, "error", backlogErr)
	} else {
		w.addStagingSize(backlog.Bytes - sizeBeforeQuery)
	}

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
				logger.Warn("UploaderMonitor: Stuck upload", "id", upload.ID, "account_id", upload.AccountID, "hash", upload.ContentHash[:16], "attempts", upload.Attempts, "age", time.Since(upload.CreatedAt).Round(time.Minute))
			}
		}
	}

	if backlogErr == nil {
		w.reportStalledBacklog(backlog)
	}

	return nil
}

// uploadStallThreshold is how old this instance's oldest unwritten upload has to get
// before the queue counts as stalled rather than busy. Attempts alone cannot express
// this state: transient S3 errors are deliberately not counted toward max_attempts
// (see processSingleUpload), so a revoked credential or a wedged endpoint produces a
// backlog that grows old with attempts pinned at 0 and stays invisible to the
// failed-upload alert above. An upload still queued an hour later has, at any sane
// retry_interval, not been progressing through retries at all.
const uploadStallThreshold = time.Hour

// uploadStallReportInterval bounds how often one stall episode is reported. The monitor
// ticks every 5 minutes and an outage lasts hours, so a per-tick warning would bury
// itself; the queue-status line at INFO still carries the per-tick detail.
const uploadStallReportInterval = time.Hour

// reportStalledBacklog warns about pending uploads that are simply old, whatever their
// attempt count. Age is the signal that matters because age is what the reaper acts on:
// these bodies exist only as files on this instance's disk, and db.CleanupFailedUploads
// deletes their messages once this instance stops looking alive.
//
// Scoped to this instance, which owns every upload it reports - the cluster-wide view of
// backlogs whose owner is already gone belongs to cleaner.reportStrandedInstances.
func (w *UploadWorker) reportStalledBacklog(backlog UploadBacklog) {
	// Publish the age unconditionally, before any threshold. The log warning below fires
	// once an hour at most, which is a poor thing to alert on; this gauge is the surface
	// an operator can actually put a rule against, and it has to keep reporting 0 while
	// the queue is healthy or a stale value would read as a stall forever.
	var oldestAge float64
	if backlog.Count > 0 && !backlog.Oldest.IsZero() {
		oldestAge = time.Since(backlog.Oldest).Seconds()
	}
	metrics.QueueProcessingLag.WithLabelValues("s3_upload").Set(oldestAge)

	if backlog.Count == 0 || backlog.Oldest.IsZero() || time.Since(backlog.Oldest) < uploadStallThreshold {
		// Drained, or still moving: the next episode is news again.
		atomic.StoreInt64(&w.lastStallReport, 0)
		return
	}

	if last := atomic.LoadInt64(&w.lastStallReport); last != 0 && time.Since(time.Unix(0, last)) < uploadStallReportInterval {
		return
	}
	atomic.StoreInt64(&w.lastStallReport, time.Now().UnixNano())

	logger.Warn("UploaderMonitor: ALERT - pending uploads are not reaching S3",
		"instance_id", w.instanceID,
		"oldest_age", time.Since(backlog.Oldest).Round(time.Minute),
		"pending", backlog.Count,
		"pending_bytes", backlog.Bytes,
		"hint", "transient S3 errors do not count toward max_attempts, so this backlog never appears in the failed-upload alert; these message bodies exist only on this instance's disk")
}

// addStagingSize applies a local write or removal to the cached staging size, so the
// limit guard reflects what happened since the last authoritative refresh in
// monitorStuckUploads rather than a value that is up to one monitor interval stale.
func (w *UploadWorker) addStagingSize(delta int64) {
	if delta == 0 {
		return
	}
	if size := atomic.AddInt64(&w.currentStagingSize, delta); size < 0 {
		// Removing files this process never counted - orphans left by a previous run -
		// can drive the running total below zero.
		atomic.CompareAndSwapInt64(&w.currentStagingSize, size, 0)
	}
}

// IsStagingLimitExceeded checks if the total staging size across the system
// plus the provided additional size exceeds the configured max staging size.
func (w *UploadWorker) IsStagingLimitExceeded(additionalSize int64) bool {
	if w.maxStagingSize <= 0 {
		return false // No limit configured
	}
	currentSize := atomic.LoadInt64(&w.currentStagingSize)
	return currentSize+additionalSize > w.maxStagingSize
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

// stagedFile is a file in the staging tree that the cleanup scan has yet to resolve
// against the pending_uploads table.
type stagedFile struct {
	path        string
	contentHash string
	size        int64
}

// orphanLookupBatchSize bounds both the number of hashes in one orphan lookup and
// how many candidates the cleanup scan holds in memory at a time.
const orphanLookupBatchSize = 500

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

	// Grace period before considering a file orphaned (1 hour).
	//
	// This must be long enough to guarantee that any DB transaction which wrote
	// the pending_upload record has either committed (making the record visible)
	// or rolled back (making the file truly orphaned) before we ever consult the
	// database.  10 minutes was too short: a large-message InsertMessage
	// transaction could still be in-flight when the cleanup ticker fired, so the
	// orphan lookup did not see a record that was about to commit.  The uploader
	// then found "no such file or directory"
	// on every retry and the message was permanently lost (see incident
	// upload id=6197517, account=22385, hash=66e220f4…).
	gracePeriod := w.cleanupGracePeriod
	if gracePeriod == 0 {
		gracePeriod = time.Hour // safe default - see SetCleanupGracePeriod
	}
	cutoffTime := time.Now().Add(-gracePeriod)

	var filesChecked, filesRemoved int64
	var totalSize int64

	stopAt, _ := filepath.Abs(w.path)

	// Candidate files grouped by account, resolved one batch at a time. A lookup
	// failure leaves its whole group on disk: an unanswered query is not evidence
	// that the message was already uploaded.
	batch := make(map[int64][]stagedFile)
	batched := 0
	removeOrphans := func(candidates map[int64][]stagedFile) {
		for accountID, files := range candidates {
			hashes := make([]string, 0, len(files))
			for _, file := range files {
				hashes = append(hashes, file.contentHash)
			}

			existing, err := w.rdb.ExistingPendingUploads(ctx, accountID, hashes)
			if err != nil {
				logger.Warn("UploaderCleanup: Failed to check pending uploads", "account_id", accountID, "files", len(files), "error", err)
				continue
			}

			for _, file := range files {
				if _, stillQueued := existing[file.contentHash]; stillQueued {
					continue
				}
				if removeErr := os.Remove(file.path); removeErr != nil {
					logger.Warn("UploaderCleanup: Failed to remove orphaned file", "path", file.path, "error", removeErr)
					continue
				}
				filesRemoved++
				totalSize += file.size
				w.addStagingSize(-file.size)
				logger.Info("UploaderCleanup: Removed orphaned file", "hash", file.contentHash, "account_id", accountID, "size", file.size)
				removeEmptyParents(file.path, stopAt)
			}
		}
	}

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

		// Parse path components.
		// filepath.SplitList splits on the OS list-separator (":" on Unix, ";"
		// on Windows) - it is intended for $PATH-style strings and is wrong here.
		// Use strings.Split with the path separator instead.
		parts := strings.Split(relPath, string(filepath.Separator))

		if len(parts) < 2 {
			logger.Warn("UploaderCleanup: Unexpected path structure", "path", relPath)
			return nil
		}

		// Get account ID and content hash
		accountIDStr := parts[0]
		contentHash := parts[len(parts)-1] // Last component is the hash

		// Parse account ID
		accountID, err := strconv.ParseInt(accountIDStr, 10, 64)
		if err != nil {
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
				w.addStagingSize(-info.Size())
				logger.Info("UploaderCleanup: Removed invalid file", "path", path)
			}
			return nil
		}

		batch[accountID] = append(batch[accountID], stagedFile{path: path, contentHash: contentHash, size: info.Size()})
		batched++
		if batched >= orphanLookupBatchSize {
			removeOrphans(batch)
			batch = make(map[int64][]stagedFile)
			batched = 0
		}

		return nil
	})

	if err == nil {
		removeOrphans(batch)
	}

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
