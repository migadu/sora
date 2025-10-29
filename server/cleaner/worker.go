package cleaner

// Package cleaner provides a worker that periodically cleans up S3 objects
// that are no longer needed, based on a grace period defined in the database.
// It uses a database table-based lock to ensure that only one instance of the
// cleanup worker is running at a time. The cleanup process involves listing
// S3 objects that are candidates for deletion and removing them from both
// S3 and the database. The worker runs at a specified interval, which can
// be configured to a minimum of 1 hour if set too small. The grace period
// is the time after which S3 objects are considered for deletion. The
// worker is designed to be started in a separate goroutine and will
// continue running until the context is done. It logs its progress and
// any errors encountered during the cleanup process.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/resilient"

	"github.com/migadu/sora/storage"
	"github.com/minio/minio-go/v7"
)

// DatabaseManager defines the interface for database operations required by the cleaner.
// This allows for mocking in tests.
type DatabaseManager interface {
	AcquireCleanupLockWithRetry(ctx context.Context) (bool, error)
	ReleaseCleanupLockWithRetry(ctx context.Context) error
	ExpungeOldMessagesWithRetry(ctx context.Context, maxAge time.Duration) (int64, error)
	CleanupFailedUploadsWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error)
	CleanupSoftDeletedAccountsWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error)
	CleanupOldVacationResponsesWithRetry(ctx context.Context, gracePeriod time.Duration) (int64, error)
	CleanupOldAuthAttemptsWithRetry(ctx context.Context, retention time.Duration) (int64, error)
	CleanupOldHealthStatusesWithRetry(ctx context.Context, retention time.Duration) (int64, error)
	GetUserScopedObjectsForCleanupWithRetry(ctx context.Context, gracePeriod time.Duration, limit int) ([]db.UserScopedObjectForCleanup, error)
	DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx context.Context, objects []db.UserScopedObjectForCleanup) (int64, error)
	PruneOldMessageBodiesWithRetry(ctx context.Context, retention time.Duration) (int64, error)
	GetUnusedContentHashesWithRetry(ctx context.Context, limit int) ([]string, error)
	DeleteMessageContentsByHashBatchWithRetry(ctx context.Context, hashes []string) (int64, error)
	GetDanglingAccountsForFinalDeletionWithRetry(ctx context.Context, limit int) ([]int64, error)
	FinalizeAccountDeletionsWithRetry(ctx context.Context, accountIDs []int64) (int64, error)
}

// S3Manager defines the interface for S3 operations required by the cleaner.
type S3Manager interface {
	DeleteWithRetry(ctx context.Context, key string) error
}

// CacheManager defines the interface for cache operations required by the cleaner.
type CacheManager interface {
	Delete(contentHash string) error
}

type CleanupWorker struct {
	rdb                   DatabaseManager
	s3                    S3Manager
	cache                 CacheManager
	interval              time.Duration
	gracePeriod           time.Duration
	maxAgeRestriction     time.Duration
	ftsRetention          time.Duration
	authAttemptsRetention time.Duration
	healthStatusRetention time.Duration
	stopCh                chan struct{}
	errCh                 chan<- error
	wg                    sync.WaitGroup
	mu                    sync.Mutex
	running               bool
}

// New creates a new CleanupWorker.
func New(rdb *resilient.ResilientDatabase, s3 *storage.S3Storage, cache *cache.Cache, interval, gracePeriod, maxAgeRestriction, ftsRetention, authAttemptsRetention, healthStatusRetention time.Duration, errCh chan<- error) *CleanupWorker {
	// Wrap S3 storage with resilient patterns including circuit breakers
	resilientS3 := resilient.NewResilientS3Storage(s3)

	return &CleanupWorker{
		rdb:                   rdb,         // *resilient.ResilientDatabase implements DatabaseManager
		s3:                    resilientS3, // *resilient.ResilientS3Storage implements S3Manager
		cache:                 cache,       // *cache.Cache implements CacheManager
		interval:              interval,
		gracePeriod:           gracePeriod,
		maxAgeRestriction:     maxAgeRestriction,
		ftsRetention:          ftsRetention,
		authAttemptsRetention: authAttemptsRetention,
		healthStatusRetention: healthStatusRetention,
		stopCh:                make(chan struct{}),
		errCh:                 errCh,
	}
}

func (w *CleanupWorker) Start(ctx context.Context) error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = true
	w.mu.Unlock()

	w.wg.Add(1)
	go w.run(ctx)

	logger.Info("[CLEANUP] worker started")
	return nil
}

func (w *CleanupWorker) run(ctx context.Context) {
	defer func() {
		w.mu.Lock()
		w.running = false
		w.mu.Unlock()
		w.wg.Done()
	}()

	var logParts []string
	logParts = append(logParts, fmt.Sprintf("interval: %v", w.interval))
	logParts = append(logParts, fmt.Sprintf("grace period: %v", w.gracePeriod))
	if w.maxAgeRestriction > 0 {
		logParts = append(logParts, fmt.Sprintf("max age restriction: %v", w.maxAgeRestriction))
	}
	logParts = append(logParts, fmt.Sprintf("FTS retention: %v", w.ftsRetention))
	logParts = append(logParts, fmt.Sprintf("auth attempts retention: %v", w.authAttemptsRetention))
	logParts = append(logParts, fmt.Sprintf("health status retention: %v", w.healthStatusRetention))

	logger.Infof("[CLEANUP] worker processing with %s", strings.Join(logParts, ", "))

	interval := w.interval
	const minAllowedInterval = time.Minute
	if interval < minAllowedInterval {
		logger.Warnf("[CLEANUP] configured interval %v is less than minimum allowed %v. Using minimum.", interval, minAllowedInterval)
		interval = minAllowedInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Process immediately on start
	if err := w.runOnce(ctx); err != nil {
		w.reportError(err)
	}

	for {
		select {
		case <-ctx.Done():
			logger.Info("[CLEANUP] worker stopped due to context cancellation")
			return
		case <-w.stopCh:
			logger.Info("[CLEANUP] worker stopped due to stop signal")
			return
		case <-ticker.C:
			logger.Info("[CLEANUP] running S3 cleanup")
			if err := w.runOnce(ctx); err != nil {
				w.reportError(err)
			}
		}
	}
}

// Stop gracefully stops the worker and waits for all goroutines to complete.
// It is safe to call Stop multiple times - subsequent calls are no-ops if already stopped.
func (w *CleanupWorker) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	w.running = false
	w.mu.Unlock()

	close(w.stopCh)
	w.wg.Wait()

	logger.Info("[CLEANUP] worker stopped")
}

func (w *CleanupWorker) runOnce(ctx context.Context) error {
	locked, err := w.rdb.AcquireCleanupLockWithRetry(ctx)
	if err != nil {
		logger.Error("[CLEANUP] failed to acquire advisory lock:", err)
		return fmt.Errorf("failed to acquire advisory lock: %w", err)
	}
	if !locked {
		logger.Info("[CLEANUP] skipped: another instance holds the cleanup lock")
		return nil
	}
	defer func() {
		if err := w.rdb.ReleaseCleanupLockWithRetry(ctx); err != nil {
			logger.Warnf("[CLEANUP] failed to release advisory lock: %v", err)
		}
	}()

	// Initialize counters for summary logging
	var failedUploadsCount, deletedAccountCount, vacationCount, authCount, healthCount int64
	var successfulDeletes []db.UserScopedObjectForCleanup
	var prunedBodiesCount, orphanHashCount, finalizedAccountCount int64

	// First handle max age restriction if configured
	if w.maxAgeRestriction > 0 {
		count, err := w.rdb.ExpungeOldMessagesWithRetry(ctx, w.maxAgeRestriction)
		if err != nil {
			logger.Errorf("[CLEANUP] failed to expunge old messages: %v", err)
			// Continue with other cleanup tasks even if this fails
		} else if count > 0 {
			logger.Infof("[CLEANUP] expunged %d messages older than %v", count, w.maxAgeRestriction)
		}
	}

	// --- Phase 0a: Cleanup of failed uploads ---
	// This removes message metadata for messages that were never successfully uploaded to S3.
	failedUploadsCount, err = w.rdb.CleanupFailedUploadsWithRetry(ctx, w.gracePeriod)
	if err != nil {
		// Log the error but continue, as other cleanup tasks can still proceed.
		logger.Errorf("[CLEANUP] failed to clean up failed uploads: %v", err)
	} else if failedUploadsCount > 0 {
		logger.Infof("[CLEANUP] cleaned up %d messages that failed to upload within the grace period", failedUploadsCount)
	}

	// --- Phase 0: Process soft-deleted accounts ---
	// This prepares accounts for deletion by expunging their messages and removing
	// associated data, making them ready for the subsequent cleanup phases.
	deletedAccountCount, err = w.rdb.CleanupSoftDeletedAccountsWithRetry(ctx, w.gracePeriod)
	if err != nil {
		logger.Errorf("[CLEANUP] failed to process soft-deleted accounts: %v", err)
	} else if deletedAccountCount > 0 {
		logger.Infof("[CLEANUP] processed %d soft-deleted accounts for hard deletion", deletedAccountCount)
	}

	// Clean up old vacation responses.
	vacationCount, err = w.rdb.CleanupOldVacationResponsesWithRetry(ctx, w.gracePeriod)
	if err != nil {
		logger.Errorf("[CLEANUP] failed to clean up old vacation responses: %v", err)
		// Continue with S3 cleanup even if vacation cleanup fails
	} else if vacationCount > 0 {
		logger.Infof("[CLEANUP] deleted %d old vacation responses", vacationCount)
	}

	// --- Cleanup of old auth attempts ---
	if w.authAttemptsRetention > 0 {
		authCount, err = w.rdb.CleanupOldAuthAttemptsWithRetry(ctx, w.authAttemptsRetention)
		if err != nil {
			logger.Errorf("[CLEANUP] failed to clean up old auth attempts: %v", err)
		} else if authCount > 0 {
			logger.Infof("[CLEANUP] deleted %d old auth attempts older than %v", authCount, w.authAttemptsRetention)
		}
	}

	// --- Cleanup of old health statuses ---
	if w.healthStatusRetention > 0 {
		healthCount, err = w.rdb.CleanupOldHealthStatusesWithRetry(ctx, w.healthStatusRetention)
		if err != nil {
			logger.Errorf("[CLEANUP] failed to clean up old health statuses: %v", err)
		} else if healthCount > 0 {
			logger.Infof("[CLEANUP] deleted %d old health statuses older than %v", healthCount, w.healthStatusRetention)
		}
	}

	// --- Phase 1: User-scoped cleanup (S3 objects and message references) ---
	// Get objects to clean up, scoped by user, as S3 storage is user-scoped.
	candidates, err := w.rdb.GetUserScopedObjectsForCleanupWithRetry(ctx, w.gracePeriod, db.BATCH_PURGE_SIZE)
	if err != nil {
		logger.Errorf("[CLEANUP] failed to list user-scoped objects for cleanup: %v", err)
		return fmt.Errorf("failed to list user-scoped objects for cleanup: %w", err)
	}

	if len(candidates) > 0 {
		logger.Infof("[CLEANUP] found %d user-scoped object groups for S3 cleanup", len(candidates))

		var failedS3Keys []string

		for _, candidate := range candidates {
			// Validate candidate data before processing
			if candidate.ContentHash == "" || candidate.S3Domain == "" || candidate.S3Localpart == "" {
				logger.Warnf("[CLEANUP] invalid candidate data - hash:%s domain:%s localpart:%s",
					candidate.ContentHash, candidate.S3Domain, candidate.S3Localpart)
				continue
			}

			// Check for context cancellation in the loop
			select {
			case <-ctx.Done():
				logger.Info("[CLEANUP] request aborted during S3 cleanup")
				return fmt.Errorf("request aborted during S3 cleanup")
			default:
			}

			s3Key := helpers.NewS3Key(candidate.S3Domain, candidate.S3Localpart, candidate.ContentHash)
			s3Err := w.s3.DeleteWithRetry(ctx, s3Key)

			isS3ObjectNotFoundError := false
			var minioErr minio.ErrorResponse
			if s3Err != nil && errors.As(s3Err, &minioErr) {
				isS3ObjectNotFoundError = (minioErr.StatusCode == 404)
			}

			if s3Err != nil && !isS3ObjectNotFoundError {
				logger.Errorf("[CLEANUP] failed to delete S3 object %s: %v", s3Key, s3Err)
				failedS3Keys = append(failedS3Keys, s3Key)
				continue // Skip to the next candidate
			}

			if isS3ObjectNotFoundError {
				logger.Infof("[CLEANUP] S3 object %s was not found. Proceeding with DB cleanup.", s3Key)
			}
			successfulDeletes = append(successfulDeletes, candidate)
		}

		if len(successfulDeletes) > 0 {
			deletedCount, err := w.rdb.DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx, successfulDeletes)
			if err != nil {
				logger.Errorf("[CLEANUP] failed to batch delete DB message rows: %v", err)
			} else {
				logger.Infof("[CLEANUP] successfully cleaned up %d user-scoped message rows in the database.", deletedCount)
			}
		}
	} else {
		logger.Info("[CLEANUP] no user-scoped objects to clean up")
	}

	// --- Phase 2a: FTS Body Pruning (for old messages) ---
	if w.ftsRetention > 0 {
		// This prunes the text_body of old messages to save space, but keeps the
		// text_body_tsv so that full-text search on the body continues to work.
		prunedBodiesCount, err = w.rdb.PruneOldMessageBodiesWithRetry(ctx, w.ftsRetention)
		if err != nil {
			logger.Errorf("[CLEANUP] failed to prune old message bodies: %v", err)
			// Continue with other cleanup tasks even if this fails
		} else if prunedBodiesCount > 0 {
			logger.Infof("[CLEANUP] pruned text_body for %d message contents older than %v", prunedBodiesCount, w.ftsRetention)
		}
	}

	// --- Phase 2b: Global resource cleanup (message_contents and cache) ---
	orphanHashes, err := w.rdb.GetUnusedContentHashesWithRetry(ctx, db.BATCH_PURGE_SIZE)
	if err != nil {
		logger.Errorf("[CLEANUP] failed to list unused content hashes for global cleanup: %v", err)
		return fmt.Errorf("failed to list unused content hashes for global cleanup: %w", err)
	}

	orphanHashCount = int64(len(orphanHashes))
	if len(orphanHashes) > 0 {
		logger.Infof("[CLEANUP] found %d orphaned content hashes for global cleanup.", len(orphanHashes))

		// Batch delete from message_contents table
		deletedCount, err := w.rdb.DeleteMessageContentsByHashBatchWithRetry(ctx, orphanHashes)
		if err != nil {
			logger.Errorf("[CLEANUP] failed to batch delete from message_contents: %v. Will be retried on next run.", err)
		} else if deletedCount > 0 {
			logger.Infof("[CLEANUP] deleted %d rows from message_contents.", deletedCount)
		}

		// Delete from local cache one by one. This is a local filesystem operation, so looping is fine.
		for _, cHash := range orphanHashes {
			if err := w.cache.Delete(cHash); err != nil {
				// This is not critical, as the cache has its own TTL and eviction policies.
				logger.Warnf("[CLEANUP] failed to delete from cache for hash %s: %v", cHash, err)
			}
		}
	} else {
		logger.Info("[CLEANUP] no orphaned content hashes to clean up")
	}

	// --- Phase 3: Final account deletion ---
	// After all associated data (S3 objects, messages, etc.) has been cleaned up,
	// we can now safely delete the 'accounts' row itself.
	danglingAccounts, err := w.rdb.GetDanglingAccountsForFinalDeletionWithRetry(ctx, db.BATCH_PURGE_SIZE)
	if err != nil {
		logger.Errorf("[CLEANUP] failed to list dangling accounts for final deletion: %v", err)
		return fmt.Errorf("failed to list dangling accounts for final deletion: %w", err)
	}

	finalizedAccountCount = int64(len(danglingAccounts))
	if len(danglingAccounts) > 0 {
		logger.Infof("[CLEANUP] found %d dangling accounts for final deletion", len(danglingAccounts))
		deletedCount, err := w.rdb.FinalizeAccountDeletionsWithRetry(ctx, danglingAccounts)
		if err != nil {
			logger.Errorf("[CLEANUP] failed to finalize deletion of account batch: %v", err)
		} else if deletedCount > 0 {
			logger.Infof("[CLEANUP] finalized deletion of %d dangling accounts", deletedCount)
			finalizedAccountCount = deletedCount
		}
	}

	// Log cleanup cycle summary for observability
	logger.Infof("[CLEANUP] cycle completed: failed_uploads=%d, soft_deleted_accounts=%d, vacation_responses=%d, auth_attempts=%d, health_statuses=%d, s3_objects=%d, pruned_bodies=%d, orphan_hashes=%d, finalized_accounts=%d",
		failedUploadsCount, deletedAccountCount, vacationCount, authCount, healthCount, len(successfulDeletes), prunedBodiesCount, orphanHashCount, finalizedAccountCount)

	return nil
}

// reportError sends an error to the error channel if configured, otherwise logs it
func (w *CleanupWorker) reportError(err error) {
	if w.errCh != nil {
		select {
		case w.errCh <- err:
		default:
			logger.Errorf("[CLEANUP] worker error (no listener): %v", err)
		}
	} else {
		logger.Errorf("[CLEANUP] worker error: %v", err)
	}
}
