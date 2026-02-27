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

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/migadu/sora/storage"
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
	CleanupOldHealthStatusesWithRetry(ctx context.Context, retention time.Duration) (int64, error)
	GetUserScopedObjectsForCleanupWithRetry(ctx context.Context, gracePeriod time.Duration, limit int) ([]db.UserScopedObjectForCleanup, error)
	DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx context.Context, objects []db.UserScopedObjectForCleanup) (int64, error)
	PruneOldMessageBodiesWithRetry(ctx context.Context, retention time.Duration) (int64, error)
	PruneOldMessageBodiesBatchedWithRetry(ctx context.Context, retention time.Duration) (int64, error)
	PruneOldMessageVectorsWithRetry(ctx context.Context, retention time.Duration) (int64, error)
	PruneOldMessageVectorsBatchedWithRetry(ctx context.Context, retention time.Duration) (int64, error)
	GetUnusedContentHashesWithRetry(ctx context.Context, limit int) ([]string, error)
	DeleteMessageContentsByHashBatchWithRetry(ctx context.Context, hashes []string) (int64, error)
	GetDanglingAccountsForFinalDeletionWithRetry(ctx context.Context, limit int) ([]int64, error)
	FinalizeAccountDeletionsWithRetry(ctx context.Context, accountIDs []int64) (int64, error)
}

// S3Manager defines the interface for S3 operations required by the cleaner.
type S3Manager interface {
	DeleteWithRetry(ctx context.Context, key string) error
	IsHealthy() bool // Check if S3 is reachable (circuit breaker state)
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
	ftsRetention          time.Duration // How long to keep FTS vectors (text_body_tsv, headers_tsv)
	ftsSourceRetention    time.Duration // How long to keep source text (text_body, headers)
	healthStatusRetention time.Duration
	stopCh                chan struct{}
	errCh                 chan<- error
	wg                    sync.WaitGroup
	mu                    sync.Mutex
	running               bool
}

// New creates a new CleanupWorker.
func New(rdb *resilient.ResilientDatabase, s3 *storage.S3Storage, cache *cache.Cache, interval, gracePeriod, maxAgeRestriction, ftsRetention, ftsSourceRetention, healthStatusRetention time.Duration, errCh chan<- error) *CleanupWorker {
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
		ftsSourceRetention:    ftsSourceRetention,
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

	logger.Info("Cleanup: worker started")
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
	if w.ftsRetention > 0 {
		logParts = append(logParts, fmt.Sprintf("FTS vector retention: %v", w.ftsRetention))
	}
	if w.ftsSourceRetention > 0 {
		logParts = append(logParts, fmt.Sprintf("FTS source retention: %v", w.ftsSourceRetention))
	}
	logParts = append(logParts, fmt.Sprintf("health status retention: %v", w.healthStatusRetention))

	logger.Info("Cleanup: Worker processing", "config", strings.Join(logParts, ", "))

	interval := w.interval
	const minAllowedInterval = time.Minute
	if interval < minAllowedInterval {
		logger.Warn("Cleanup: Configured interval less than minimum - using minimum", "interval", interval, "minimum", minAllowedInterval)
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
			logger.Info("Cleanup: worker stopped due to context cancellation")
			return
		case <-w.stopCh:
			logger.Info("Cleanup: worker stopped due to stop signal")
			return
		case <-ticker.C:
			logger.Info("Cleanup: running S3 cleanup")
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

	logger.Info("Cleanup: worker stopped")
}

func (w *CleanupWorker) runOnce(ctx context.Context) error {
	locked, err := w.rdb.AcquireCleanupLockWithRetry(ctx)
	if err != nil {
		logger.Error("Cleanup: failed to acquire advisory lock:", err)
		return fmt.Errorf("failed to acquire advisory lock: %w", err)
	}
	if !locked {
		logger.Info("Cleanup: skipped: another instance holds the cleanup lock")
		return nil
	}
	defer func() {
		if err := w.rdb.ReleaseCleanupLockWithRetry(ctx); err != nil {
			logger.Warn("Cleanup: Failed to release advisory lock", "error", err)
		}
	}()

	// Initialize counters for summary logging
	var failedUploadsCount, deletedAccountCount, vacationCount, healthCount int64
	var successfulDeletes []db.UserScopedObjectForCleanup
	var prunedBodiesCount, orphanHashCount, finalizedAccountCount int64

	// First handle max age restriction if configured
	if w.maxAgeRestriction > 0 {
		count, err := w.rdb.ExpungeOldMessagesWithRetry(ctx, w.maxAgeRestriction)
		if err != nil {
			logger.Error("Cleanup: Failed to expunge old messages", "error", err)
			// Continue with other cleanup tasks even if this fails
		} else if count > 0 {
			logger.Info("Cleanup: Expunged old messages", "count", count, "max_age", w.maxAgeRestriction)
		}
	}

	// --- Phase 0a: Cleanup of failed uploads ---
	// This removes message metadata for messages that were never successfully uploaded to S3.
	// SAFETY: Only run when S3 is healthy. If S3 is down, messages can't be uploaded,
	// and deleting their metadata would cause permanent message loss.
	if !w.s3.IsHealthy() {
		logger.Warn("Cleanup: Skipping failed upload cleanup — S3 is unhealthy (circuit breaker open). Messages preserved for retry when S3 recovers.")
	} else {
		failedUploadsCount, err = w.rdb.CleanupFailedUploadsWithRetry(ctx, w.gracePeriod)
		if err != nil {
			// Log the error but continue, as other cleanup tasks can still proceed.
			logger.Error("Cleanup: Failed to clean up failed uploads", "error", err)
		} else if failedUploadsCount > 0 {
			logger.Info("Cleanup: Cleaned up failed upload messages", "count", failedUploadsCount)
		}
	} // end S3 healthy check

	// --- Phase 0: Process soft-deleted accounts ---
	// This prepares accounts for deletion by expunging their messages and removing
	// associated data, making them ready for the subsequent cleanup phases.
	deletedAccountCount, err = w.rdb.CleanupSoftDeletedAccountsWithRetry(ctx, w.gracePeriod)
	if err != nil {
		logger.Error("Cleanup: Failed to process soft-deleted accounts", "error", err)
	} else if deletedAccountCount > 0 {
		logger.Info("Cleanup: Processed soft-deleted accounts", "count", deletedAccountCount)
	}

	// Clean up old vacation responses.
	vacationCount, err = w.rdb.CleanupOldVacationResponsesWithRetry(ctx, w.gracePeriod)
	if err != nil {
		logger.Error("Cleanup: Failed to clean up old vacation responses", "error", err)
		// Continue with S3 cleanup even if vacation cleanup fails
	} else if vacationCount > 0 {
		logger.Info("Cleanup: Deleted old vacation responses", "count", vacationCount)
	}

	// --- Cleanup of old health statuses ---
	if w.healthStatusRetention > 0 {
		healthCount, err = w.rdb.CleanupOldHealthStatusesWithRetry(ctx, w.healthStatusRetention)
		if err != nil {
			logger.Error("Cleanup: Failed to clean up old health statuses", "error", err)
		} else if healthCount > 0 {
			logger.Info("Cleanup: Deleted old health statuses", "count", healthCount, "retention", w.healthStatusRetention)
		}
	}

	// --- Phase 1: User-scoped cleanup (S3 objects and message references) ---
	// Get objects to clean up, scoped by user, as S3 storage is user-scoped.
	candidates, err := w.rdb.GetUserScopedObjectsForCleanupWithRetry(ctx, w.gracePeriod, db.BATCH_PURGE_SIZE)
	if err != nil {
		logger.Error("Cleanup: Failed to list user-scoped objects for cleanup", "error", err)
		return fmt.Errorf("failed to list user-scoped objects for cleanup: %w", err)
	}

	if len(candidates) > 0 {
		logger.Info("Cleanup: Found user-scoped object groups for S3 cleanup", "count", len(candidates))

		var failedS3Keys []string

		for _, candidate := range candidates {
			// Validate candidate data before processing
			if candidate.ContentHash == "" || candidate.S3Domain == "" || candidate.S3Localpart == "" {
				logger.Warn("Cleanup: Invalid candidate data", "hash", candidate.ContentHash, "domain", candidate.S3Domain, "localpart", candidate.S3Localpart)
				continue
			}

			// Check for context cancellation in the loop
			select {
			case <-ctx.Done():
				logger.Info("Cleanup: request aborted during S3 cleanup")
				return fmt.Errorf("request aborted during S3 cleanup")
			default:
			}

			s3Key := helpers.NewS3Key(candidate.S3Domain, candidate.S3Localpart, candidate.ContentHash)
			s3Err := w.s3.DeleteWithRetry(ctx, s3Key)

			isS3ObjectNotFoundError := false
			var awsErr *awshttp.ResponseError
			if s3Err != nil && errors.As(s3Err, &awsErr) {
				isS3ObjectNotFoundError = (awsErr.HTTPStatusCode() == 404)
			}

			if s3Err != nil && !isS3ObjectNotFoundError {
				logger.Error("Cleanup: Failed to delete S3 object", "key", s3Key, "error", s3Err)
				failedS3Keys = append(failedS3Keys, s3Key)
				continue // Skip to the next candidate
			}

			if isS3ObjectNotFoundError {
				logger.Info("Cleanup: S3 object not found - proceeding with DB cleanup", "key", s3Key)
			}
			successfulDeletes = append(successfulDeletes, candidate)
		}

		if len(successfulDeletes) > 0 {
			deletedCount, err := w.rdb.DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx, successfulDeletes)
			if err != nil {
				logger.Error("Cleanup: Failed to batch delete DB message rows", "error", err)
			} else {
				logger.Info("Cleanup: Successfully cleaned up user-scoped message rows", "count", deletedCount)
			}
		}
	} else {
		logger.Info("Cleanup: no user-scoped objects to clean up")
	}

	// --- Phase 2a: FTS Source Text Pruning (for old messages) ---
	if w.ftsSourceRetention > 0 {
		// This prunes text_body and headers of old messages to save space, but keeps
		// text_body_tsv and headers_tsv so that full-text search continues to work.
		// Use the batched version which commits between batches to avoid timeout issues.
		prunedBodiesCount, err = w.rdb.PruneOldMessageBodiesBatchedWithRetry(ctx, w.ftsSourceRetention)
		if err != nil {
			logger.Error("Cleanup: Failed to prune old message source text", "error", err)
			// Continue with other cleanup tasks even if this fails
		} else if prunedBodiesCount > 0 {
			logger.Info("Cleanup: Pruned text_body for old message contents", "count", prunedBodiesCount, "age", w.ftsSourceRetention)
		}
	}

	// --- Phase 2a2: FTS Vector Pruning (for very old messages) ---
	if w.ftsRetention > 0 {
		// This prunes text_body_tsv and headers_tsv of old messages, completely removing search capability.
		// This is more aggressive than source pruning - use with caution.
		// Use the batched version which commits between batches to avoid timeout issues.
		prunedVectorsCount, err := w.rdb.PruneOldMessageVectorsBatchedWithRetry(ctx, w.ftsRetention)
		if err != nil {
			logger.Error("Cleanup: Failed to prune old message vectors", "error", err)
			// Continue with other cleanup tasks even if this fails
		} else if prunedVectorsCount > 0 {
			logger.Info("Cleanup: Pruned text_body_tsv for old message contents", "count", prunedVectorsCount, "age", w.ftsRetention)
		}
	}

	// --- Phase 2b: Global resource cleanup (message_contents and cache) ---
	orphanHashes, err := w.rdb.GetUnusedContentHashesWithRetry(ctx, db.BATCH_PURGE_SIZE)
	if err != nil {
		logger.Error("Cleanup: Failed to list unused content hashes for global cleanup", "error", err)
		return fmt.Errorf("failed to list unused content hashes for global cleanup: %w", err)
	}

	orphanHashCount = int64(len(orphanHashes))
	if len(orphanHashes) > 0 {
		logger.Info("Cleanup: Found orphaned content hashes for global cleanup", "count", len(orphanHashes))

		// Batch delete from message_contents table
		deletedCount, err := w.rdb.DeleteMessageContentsByHashBatchWithRetry(ctx, orphanHashes)
		if err != nil {
			logger.Error("Cleanup: Failed to batch delete from message_contents - will be retried on next run", "error", err)
		} else if deletedCount > 0 {
			logger.Info("Cleanup: Deleted rows from message_contents", "count", deletedCount)
		}

		// Delete from local cache one by one. This is a local filesystem operation, so looping is fine.
		for _, cHash := range orphanHashes {
			if err := w.cache.Delete(cHash); err != nil {
				// This is not critical, as the cache has its own TTL and eviction policies.
				logger.Warn("Cleanup: Failed to delete from cache", "hash", cHash, "error", err)
			}
		}
	} else {
		logger.Info("Cleanup: no orphaned content hashes to clean up")
	}

	// --- Phase 3: Final account deletion ---
	// After all associated data (S3 objects, messages, etc.) has been cleaned up,
	// we can now safely delete the 'accounts' row itself.
	danglingAccounts, err := w.rdb.GetDanglingAccountsForFinalDeletionWithRetry(ctx, db.BATCH_PURGE_SIZE)
	if err != nil {
		logger.Error("Cleanup: Failed to list dangling accounts for final deletion", "error", err)
		return fmt.Errorf("failed to list dangling accounts for final deletion: %w", err)
	}

	finalizedAccountCount = int64(len(danglingAccounts))
	if len(danglingAccounts) > 0 {
		logger.Info("Cleanup: Found dangling accounts for final deletion", "count", len(danglingAccounts))
		deletedCount, err := w.rdb.FinalizeAccountDeletionsWithRetry(ctx, danglingAccounts)
		if err != nil {
			logger.Error("Cleanup: Failed to finalize deletion of account batch", "error", err)
		} else if deletedCount > 0 {
			logger.Info("Cleanup: Finalized deletion of dangling accounts", "count", deletedCount)
			finalizedAccountCount = deletedCount
		}
	}

	// Log cleanup cycle summary for observability
	logger.Info("Cleanup: Cycle completed", "failed_uploads", failedUploadsCount,
		"soft_deleted_accounts", deletedAccountCount, "vacation_responses", vacationCount,
		"health_statuses", healthCount, "s3_objects", len(successfulDeletes),
		"pruned_bodies", prunedBodiesCount, "orphan_hashes", orphanHashCount, "finalized_accounts", finalizedAccountCount)

	return nil
}

// reportError sends an error to the error channel if configured, otherwise logs it
func (w *CleanupWorker) reportError(err error) {
	if w.errCh != nil {
		select {
		case w.errCh <- err:
		default:
			logger.Error("Cleanup: Worker error (no listener)", "error", err)
		}
	} else {
		logger.Error("Cleanup: Worker error", "error", err)
	}
}
