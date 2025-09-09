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
	"time"

	"github.com/migadu/sora/cache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"

	"github.com/migadu/sora/storage"
	"github.com/minio/minio-go/v7"
)

type CleanupWorker struct {
	db                *db.Database
	s3                *storage.S3Storage
	cache             *cache.Cache
	interval          time.Duration
	gracePeriod       time.Duration
	maxAgeRestriction time.Duration
}

// New creates a new CleanupWorker.
func New(db *db.Database, s3 *storage.S3Storage, cache *cache.Cache, interval, gracePeriod, maxAgeRestriction time.Duration) *CleanupWorker {
	return &CleanupWorker{
		db:                db,
		s3:                s3,
		cache:             cache,
		interval:          interval,
		gracePeriod:       gracePeriod,
		maxAgeRestriction: maxAgeRestriction,
	}
}

func (w *CleanupWorker) Start(ctx context.Context) {
	if w.maxAgeRestriction > 0 {
		log.Printf("[CLEANUP] worker starting with interval: %v, grace period: %v, max age restriction: %v", w.interval, w.gracePeriod, w.maxAgeRestriction)
	} else {
		log.Printf("[CLEANUP] worker starting with interval: %v, grace period: %v", w.interval, w.gracePeriod)
	}
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
				log.Println("[CLEANUP] worker stopped")
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

func (w *CleanupWorker) runOnce(ctx context.Context) error {
	locked, err := w.db.AcquireCleanupLock(ctx)
	if err != nil {
		log.Println("[CLEANUP] failed to acquire advisory lock:", err)
		return fmt.Errorf("failed to acquire advisory lock: %w", err)
	}
	if !locked {
		log.Println("[CLEANUP] skipped: another instance is running it")
		return nil
	}
	defer w.db.ReleaseCleanupLock(ctx)

	// First handle max age restriction if configured
	if w.maxAgeRestriction > 0 {
		count, err := w.db.ExpungeOldMessages(ctx, w.maxAgeRestriction)
		if err != nil {
			log.Printf("[CLEANUP] failed to expunge old messages: %v", err)
			// Continue with other cleanup tasks even if this fails
		} else if count > 0 {
			log.Printf("[CLEANUP] expunged %d messages older than %v", count, w.maxAgeRestriction)
		}
	}

	// --- Phase 0: Process soft-deleted accounts ---
	// This prepares accounts for deletion by expunging their messages and removing
	// associated data, making them ready for the subsequent cleanup phases.
	deletedAccountCount, err := w.db.CleanupSoftDeletedAccounts(ctx, w.gracePeriod)
	if err != nil {
		log.Printf("[CLEANUP] failed to process soft-deleted accounts: %v", err)
	} else if deletedAccountCount > 0 {
		log.Printf("[CLEANUP] processed %d soft-deleted accounts for hard deletion", deletedAccountCount)
	}

	// Clean up old vacation responses
	count, err := w.db.CleanupOldVacationResponses(ctx, w.gracePeriod)
	if err != nil {
		log.Printf("[CLEANUP] failed to clean up old vacation responses: %v", err)
		// Continue with S3 cleanup even if vacation cleanup fails
	} else if count > 0 {
		log.Printf("[CLEANUP] deleted %d old vacation responses", count)
	}

	// --- Phase 1: User-scoped cleanup (S3 objects and message references) ---
	// Get objects to clean up, scoped by user, as S3 storage is user-scoped.
	candidates, err := w.db.GetUserScopedObjectsForCleanup(ctx, w.gracePeriod, db.BATCH_PURGE_SIZE)
	if err != nil {
		log.Printf("[CLEANUP] failed to list user-scoped objects for cleanup: %v", err)
		return fmt.Errorf("failed to list user-scoped objects for cleanup: %w", err)
	}

	if len(candidates) > 0 {
		log.Printf("[CLEANUP] found %d user-scoped objects for S3 cleanup", len(candidates))
		for _, candidate := range candidates {
			s3Key := helpers.NewS3Key(candidate.S3Domain, candidate.S3Localpart, candidate.ContentHash)
			log.Printf("[CLEANUP] deleting user-scoped object for account %d: %s", candidate.AccountID, s3Key)

			cHash := candidate.ContentHash // Keep a local copy for logging
			s3Err := w.s3.Delete(s3Key)

			// Check if the error indicates the object was not found (HTTP 404)
			isS3ObjectNotFoundError := false
			var minioErr minio.ErrorResponse
			if s3Err != nil && errors.As(s3Err, &minioErr) {
				if minioErr.StatusCode == 404 {
					isS3ObjectNotFoundError = true
				}
			}

			// If S3 deletion failed AND it was NOT a 'not found' error, log and skip DB delete.
			if s3Err != nil && !isS3ObjectNotFoundError {
				log.Printf("[CLEANUP] failed to delete S3 object %s: %v", s3Key, s3Err)
				continue // Skip to the next candidate
			}

			if isS3ObjectNotFoundError {
				log.Printf("[CLEANUP] S3 object %s was not found. Proceeding with DB cleanup.", s3Key)
			}

			if err := w.db.DeleteExpungedMessagesByS3KeyParts(ctx, candidate.AccountID, candidate.S3Domain, candidate.S3Localpart, cHash); err != nil {
				// Log the error but continue processing other candidates.
				// The advisory lock is held, so we don't want to block. The next run will pick it up.
				log.Printf("[CLEANUP] failed to delete DB message rows for account %d and S3 key parts (%s/%s/%s): %v", candidate.AccountID, candidate.S3Domain, candidate.S3Localpart, cHash, err)
				continue
			}

			log.Printf("[CLEANUP] successfully cleaned up user-scoped resources for account %d and hash %s", candidate.AccountID, cHash)
		}
	} else {
		log.Println("[CLEANUP] no user-scoped objects to clean up")
	}

	// --- Phase 2: Global resource cleanup (message_contents and cache) ---
	orphanHashes, err := w.db.GetUnusedContentHashes(ctx, db.BATCH_PURGE_SIZE)
	if err != nil {
		log.Printf("[CLEANUP] failed to list unused content hashes for global cleanup: %v", err)
		return fmt.Errorf("failed to list unused content hashes for global cleanup: %w", err)
	}

	if len(orphanHashes) > 0 {
		log.Printf("[CLEANUP] found %d orphaned content hashes for global cleanup", len(orphanHashes))
		for _, cHash := range orphanHashes {
			log.Printf("[CLEANUP] cleaning up global resources for hash %s", cHash)

			// Delete from message_contents table
			if err := w.db.DeleteMessageContentByHash(ctx, cHash); err != nil {
				log.Printf("[CLEANUP] failed to delete from message_contents for hash %s: %v", cHash, err)
				// Continue to next hash, as this might be a transient error.
				// The next cleanup run will pick it up again.
				continue
			}

			// Delete from local cache
			if err := w.cache.Delete(cHash); err != nil {
				// This is not critical, as the cache has its own TTL and eviction policies.
				log.Printf("[CLEANUP] failed to delete from cache for hash %s: %v", cHash, err)
			}
		}
	} else {
		log.Println("[CLEANUP] no orphaned content hashes to clean up")
	}

	// --- Phase 3: Final account deletion ---
	// After all associated data (S3 objects, messages, etc.) has been cleaned up,
	// we can now safely delete the 'accounts' row itself.
	danglingAccounts, err := w.db.GetDanglingAccountsForFinalDeletion(ctx, db.BATCH_PURGE_SIZE)
	if err != nil {
		log.Printf("[CLEANUP] failed to list dangling accounts for final deletion: %v", err)
		return fmt.Errorf("failed to list dangling accounts for final deletion: %w", err)
	}

	if len(danglingAccounts) > 0 {
		log.Printf("[CLEANUP] found %d dangling accounts for final deletion", len(danglingAccounts))
		for _, accountID := range danglingAccounts {
			if err := w.db.FinalizeAccountDeletion(ctx, accountID); err != nil {
				log.Printf("[CLEANUP] failed to finalize deletion of account %d: %v", accountID, err)
			}
		}
	}

	return nil
}
