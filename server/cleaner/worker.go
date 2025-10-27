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
	"log"
	"strings"
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
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
}

// New creates a new CleanupWorker.
func New(rdb *resilient.ResilientDatabase, s3 *storage.S3Storage, cache *cache.Cache, interval, gracePeriod, maxAgeRestriction, ftsRetention, authAttemptsRetention, healthStatusRetention time.Duration) *CleanupWorker {
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
	}
}

func (w *CleanupWorker) Start(ctx context.Context) {
	var logParts []string
	logParts = append(logParts, fmt.Sprintf("interval: %v", w.interval))
	logParts = append(logParts, fmt.Sprintf("grace period: %v", w.gracePeriod))
	if w.maxAgeRestriction > 0 {
		logParts = append(logParts, fmt.Sprintf("max age restriction: %v", w.maxAgeRestriction))
	}
	logParts = append(logParts, fmt.Sprintf("FTS retention: %v", w.ftsRetention))
	logParts = append(logParts, fmt.Sprintf("auth attempts retention: %v", w.authAttemptsRetention))
	logParts = append(logParts, fmt.Sprintf("health status retention: %v", w.healthStatusRetention))

	log.Printf("[CLEANUP] worker starting with %s", strings.Join(logParts, ", "))
	interval := w.interval

	const minAllowedInterval = time.Minute
	if interval < minAllowedInterval {
		log.Printf("[CLEANUP] WARNING: configured interval %v is less than minimum allowed %v. Using minimum.", interval, minAllowedInterval)
		interval = minAllowedInterval
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				log.Println("[CLEANUP] worker stopped due to context cancellation")
				return
			case <-w.stopCh:
				log.Println("[CLEANUP] worker stopped due to stop signal")
				return
			case <-ticker.C:
				log.Println("[CLEANUP] running S3 cleanup")
				if err := w.runOnce(ctx); err != nil {
					log.Printf("[CLEANUP] error: %v", err)
				}
			}
		}
	}()
}

// Stop signals the cleanup worker to stop
func (w *CleanupWorker) Stop() {
	close(w.stopCh)
}

func (w *CleanupWorker) runOnce(ctx context.Context) error {
	locked, err := w.rdb.AcquireCleanupLockWithRetry(ctx)
	if err != nil {
		log.Println("[CLEANUP] failed to acquire advisory lock:", err)
		return fmt.Errorf("failed to acquire advisory lock: %w", err)
	}
	if !locked {
		log.Println("[CLEANUP] skipped: another instance holds the cleanup lock")
		return nil
	}
	defer func() {
		if err := w.rdb.ReleaseCleanupLockWithRetry(ctx); err != nil {
			log.Printf("[CLEANUP] WARNING: failed to release advisory lock: %v", err)
		}
	}()

	// First handle max age restriction if configured
	if w.maxAgeRestriction > 0 {
		count, err := w.rdb.ExpungeOldMessagesWithRetry(ctx, w.maxAgeRestriction)
		if err != nil {
			log.Printf("[CLEANUP] failed to expunge old messages: %v", err)
			// Continue with other cleanup tasks even if this fails
		} else if count > 0 {
			log.Printf("[CLEANUP] expunged %d messages older than %v", count, w.maxAgeRestriction)
		}
	}

	// --- Phase 0a: Cleanup of failed uploads ---
	// This removes message metadata for messages that were never successfully uploaded to S3.
	failedUploadsCount, err := w.rdb.CleanupFailedUploadsWithRetry(ctx, w.gracePeriod)
	if err != nil {
		// Log the error but continue, as other cleanup tasks can still proceed.
		log.Printf("[CLEANUP] failed to clean up failed uploads: %v", err)
	} else if failedUploadsCount > 0 {
		log.Printf("[CLEANUP] cleaned up %d messages that failed to upload within the grace period", failedUploadsCount)
	}

	// --- Phase 0: Process soft-deleted accounts ---
	// This prepares accounts for deletion by expunging their messages and removing
	// associated data, making them ready for the subsequent cleanup phases.
	deletedAccountCount, err := w.rdb.CleanupSoftDeletedAccountsWithRetry(ctx, w.gracePeriod)
	if err != nil {
		log.Printf("[CLEANUP] failed to process soft-deleted accounts: %v", err)
	} else if deletedAccountCount > 0 {
		log.Printf("[CLEANUP] processed %d soft-deleted accounts for hard deletion", deletedAccountCount)
	}

	// Clean up old vacation responses.
	count, err := w.rdb.CleanupOldVacationResponsesWithRetry(ctx, w.gracePeriod)
	if err != nil {
		log.Printf("[CLEANUP] failed to clean up old vacation responses: %v", err)
		// Continue with S3 cleanup even if vacation cleanup fails
	} else if count > 0 {
		log.Printf("[CLEANUP] deleted %d old vacation responses", count)
	}

	// --- Cleanup of old auth attempts ---
	if w.authAttemptsRetention > 0 {
		authCount, err := w.rdb.CleanupOldAuthAttemptsWithRetry(ctx, w.authAttemptsRetention)
		if err != nil {
			log.Printf("[CLEANUP] failed to clean up old auth attempts: %v", err)
		} else if authCount > 0 {
			log.Printf("[CLEANUP] deleted %d old auth attempts older than %v", authCount, w.authAttemptsRetention)
		}
	}

	// --- Cleanup of old health statuses ---
	if w.healthStatusRetention > 0 {
		healthCount, err := w.rdb.CleanupOldHealthStatusesWithRetry(ctx, w.healthStatusRetention)
		if err != nil {
			log.Printf("[CLEANUP] failed to clean up old health statuses: %v", err)
		} else if healthCount > 0 {
			log.Printf("[CLEANUP] deleted %d old health statuses older than %v", healthCount, w.healthStatusRetention)
		}
	}

	// --- Phase 1: User-scoped cleanup (S3 objects and message references) ---
	// Get objects to clean up, scoped by user, as S3 storage is user-scoped.
	candidates, err := w.rdb.GetUserScopedObjectsForCleanupWithRetry(ctx, w.gracePeriod, db.BATCH_PURGE_SIZE)
	if err != nil {
		log.Printf("[CLEANUP] failed to list user-scoped objects for cleanup: %v", err)
		return fmt.Errorf("failed to list user-scoped objects for cleanup: %w", err)
	}

	if len(candidates) > 0 {
		log.Printf("[CLEANUP] found %d user-scoped object groups for S3 cleanup", len(candidates))

		var successfulDeletes []db.UserScopedObjectForCleanup
		var failedS3Keys []string

		for _, candidate := range candidates {
			// Validate candidate data before processing
			if candidate.ContentHash == "" || candidate.S3Domain == "" || candidate.S3Localpart == "" {
				log.Printf("[CLEANUP] WARNING: invalid candidate data - hash:%s domain:%s localpart:%s",
					candidate.ContentHash, candidate.S3Domain, candidate.S3Localpart)
				continue
			}

			// Check for context cancellation in the loop
			select {
			case <-ctx.Done():
				log.Println("[CLEANUP] request aborted during S3 cleanup")
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
				log.Printf("[CLEANUP] failed to delete S3 object %s: %v", s3Key, s3Err)
				failedS3Keys = append(failedS3Keys, s3Key)
				continue // Skip to the next candidate
			}

			if isS3ObjectNotFoundError {
				log.Printf("[CLEANUP] S3 object %s was not found. Proceeding with DB cleanup.", s3Key)
			}
			successfulDeletes = append(successfulDeletes, candidate)
		}

		if len(successfulDeletes) > 0 {
			deletedCount, err := w.rdb.DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx, successfulDeletes)
			if err != nil {
				log.Printf("[CLEANUP] failed to batch delete DB message rows: %v", err)
			} else {
				log.Printf("[CLEANUP] successfully cleaned up %d user-scoped message rows in the database.", deletedCount)
			}
		}
	} else {
		log.Println("[CLEANUP] no user-scoped objects to clean up")
	}

	// --- Phase 2a: FTS Body Pruning (for old messages) ---
	if w.ftsRetention > 0 {
		// This prunes the text_body of old messages to save space, but keeps the
		// text_body_tsv so that full-text search on the body continues to work.
		count, err := w.rdb.PruneOldMessageBodiesWithRetry(ctx, w.ftsRetention)
		if err != nil {
			log.Printf("[CLEANUP] failed to prune old message bodies: %v", err)
			// Continue with other cleanup tasks even if this fails
		} else if count > 0 {
			log.Printf("[CLEANUP] pruned text_body for %d message contents older than %v", count, w.ftsRetention)
		}
	}

	// --- Phase 2b: Global resource cleanup (message_contents and cache) ---
	orphanHashes, err := w.rdb.GetUnusedContentHashesWithRetry(ctx, db.BATCH_PURGE_SIZE)
	if err != nil {
		log.Printf("[CLEANUP] failed to list unused content hashes for global cleanup: %v", err)
		return fmt.Errorf("failed to list unused content hashes for global cleanup: %w", err)
	}

	if len(orphanHashes) > 0 {
		log.Printf("[CLEANUP] found %d orphaned content hashes for global cleanup.", len(orphanHashes))

		// Batch delete from message_contents table
		deletedCount, err := w.rdb.DeleteMessageContentsByHashBatchWithRetry(ctx, orphanHashes)
		if err != nil {
			log.Printf("[CLEANUP] failed to batch delete from message_contents: %v. Will be retried on next run.", err)
		} else if deletedCount > 0 {
			log.Printf("[CLEANUP] deleted %d rows from message_contents.", deletedCount)
		}

		// Delete from local cache one by one. This is a local filesystem operation, so looping is fine.
		for _, cHash := range orphanHashes {
			if err := w.cache.Delete(cHash); err != nil {
				// This is not critical, as the cache has its own TTL and eviction policies.
				log.Printf("[CLEANUP] WARNING: failed to delete from cache for hash %s: %v", cHash, err)
			}
		}
	} else {
		log.Println("[CLEANUP] no orphaned content hashes to clean up")
	}

	// --- Phase 3: Final account deletion ---
	// After all associated data (S3 objects, messages, etc.) has been cleaned up,
	// we can now safely delete the 'accounts' row itself.
	danglingAccounts, err := w.rdb.GetDanglingAccountsForFinalDeletionWithRetry(ctx, db.BATCH_PURGE_SIZE)
	if err != nil {
		log.Printf("[CLEANUP] failed to list dangling accounts for final deletion: %v", err)
		return fmt.Errorf("failed to list dangling accounts for final deletion: %w", err)
	}

	if len(danglingAccounts) > 0 {
		log.Printf("[CLEANUP] found %d dangling accounts for final deletion", len(danglingAccounts))
		deletedCount, err := w.rdb.FinalizeAccountDeletionsWithRetry(ctx, danglingAccounts)
		if err != nil {
			log.Printf("[CLEANUP] failed to finalize deletion of account batch: %v", err)
		} else if deletedCount > 0 {
			log.Printf("[CLEANUP] finalized deletion of %d dangling accounts", deletedCount)
		}
	}

	return nil
}
