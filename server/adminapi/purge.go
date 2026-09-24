package adminapi

// purge.go - Immediate, irreversible account deletion for the admin API.
//
// This is the HTTP counterpart of `sora-admin accounts delete --purge`. It
// deliberately keeps its own copy of the expunge-then-cleanup sequence rather
// than sharing one with the CLI: the CLI reports progress to a terminal and
// builds its own S3 client from a config file, while here everything goes to
// the server log and reuses the server's storage. If the deletion sequence
// changes in one place, review the other.

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/logger"
)

// purgeBatchSize is how many uploaded objects are fetched and deleted per round.
const purgeBatchSize = 1000

// purgeAccount permanently deletes an account and all of its data (messages,
// S3 objects, mailboxes, credentials) with no grace period. It is irreversible
// and cannot be undone with /restore.
func (s *Server) purgeAccount(ctx context.Context, w http.ResponseWriter, email string) {
	if s.storage == nil {
		s.writeError(w, http.StatusServiceUnavailable, "Purge unavailable: no object storage configured")
		return
	}

	accountID, err := s.rdb.GetAccountIDByEmailWithRetry(ctx, email)
	if err != nil {
		if errors.Is(err, consts.ErrUserNotFound) {
			s.writeError(w, http.StatusNotFound, err.Error())
			return
		}
		logger.Warn("HTTP API: Error looking up account for purge", "name", s.name, "email", email, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Error purging account")
		return
	}

	// Detach from the request: a purge is destructive and can outlive both the
	// server's WriteTimeout and an impatient client. Cancelling it midway would
	// leave the account half-deleted.
	ctx = context.WithoutCancel(ctx)

	logger.Info("HTTP API: Purging account", "name", s.name, "email", email, "account_id", accountID)

	stats, err := s.purgeAccountData(ctx, accountID, email)
	if err != nil {
		// The purge is resumable: messages are only removed from the database
		// once their S3 objects are gone, so retrying continues where it stopped.
		logger.Warn("HTTP API: Error purging account", "name", s.name, "email", email, "account_id", accountID,
			"s3_objects_deleted", stats.s3Objects, "messages_deleted", stats.messages, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Error purging account, data may be partially deleted: "+err.Error())
		return
	}

	logger.Info("HTTP API: Account purged", "name", s.name, "email", email, "account_id", accountID,
		"messages_expunged", stats.expunged, "s3_objects_deleted", stats.s3Objects, "messages_deleted", stats.messages)

	s.writeJSON(w, http.StatusOK, map[string]any{
		"email":              email,
		"messages_expunged":  stats.expunged,
		"s3_objects_deleted": stats.s3Objects,
		"messages_deleted":   stats.messages,
		"message":            "Account purged successfully. All data (messages, mailboxes, credentials) has been permanently deleted.",
	})
}

// purgeStats records what a purge removed, including on the error path so a
// partial purge can be reported.
type purgeStats struct {
	expunged  int64
	s3Objects int
	messages  int64
}

// purgeAccountData deletes every trace of an account. Messages are expunged
// first so they can safely be deleted, then S3 objects and their database rows
// go in batches, and finally the mailboxes, credentials and the account itself.
func (s *Server) purgeAccountData(ctx context.Context, accountID int64, email string) (purgeStats, error) {
	var stats purgeStats

	// Mark all messages as expunged (atomic, idempotent). Even if this reports 0
	// because a previous run already did it, we still look for leftover S3 objects.
	expunged, err := s.rdb.ExpungeAllMessagesForAccount(ctx, accountID)
	if err != nil {
		return stats, fmt.Errorf("failed to expunge messages: %w", err)
	}
	stats.expunged = expunged
	logger.Debug("HTTP API: Purge expunged messages", "name", s.name, "email", email, "count", expunged)

	// Delete S3 objects and their rows in batches: fetch -> delete from S3 ->
	// delete from the database. Rows are only dropped for objects that really
	// left S3, which is what makes an interrupted purge safe to repeat.
	for {
		// GetAllUploadedObjectsForAccount filters on uploaded = TRUE, and each
		// iteration deletes what it returned, so this acts as pagination.
		batch, err := s.rdb.GetAllUploadedObjectsForAccount(ctx, accountID, purgeBatchSize)
		if err != nil {
			return stats, fmt.Errorf("failed to scan S3 objects: %w", err)
		}
		if len(batch) == 0 {
			break
		}

		s3Keys := make([]string, 0, len(batch))
		keyToCandidate := make(map[string]db.UserScopedObjectForCleanup, len(batch))
		for _, candidate := range batch {
			s3Key := helpers.NewS3Key(candidate.S3Domain, candidate.S3Localpart, candidate.ContentHash)
			s3Keys = append(s3Keys, s3Key)
			keyToCandidate[s3Key] = candidate
		}

		var deletedFromS3 []db.UserScopedObjectForCleanup
		var failed int
		for s3Key, deleteErr := range s.storage.DeleteBulk(s3Keys) {
			logger.Warn("HTTP API: Purge failed to delete S3 object", "name", s.name, "email", email, "key", s3Key, "error", deleteErr)
			failed++
			delete(keyToCandidate, s3Key)
		}
		for _, candidate := range keyToCandidate {
			deletedFromS3 = append(deletedFromS3, candidate)
		}
		stats.s3Objects += len(deletedFromS3)

		if len(deletedFromS3) == 0 {
			// Nothing left S3, so the next iteration would fetch the same batch
			// forever. Stop instead of spinning.
			return stats, fmt.Errorf("failed to delete any S3 objects in current batch (%d failed)", failed)
		}

		deleted, err := s.rdb.DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(ctx, deletedFromS3)
		if err != nil {
			return stats, fmt.Errorf("failed to delete messages from DB: %w", err)
		}
		stats.messages += deleted

		logger.Debug("HTTP API: Purge deleted batch", "name", s.name, "email", email,
			"s3_objects", len(deletedFromS3), "messages", deleted, "s3_failures", failed)
	}

	if err := s.rdb.PurgeMailboxesForAccount(ctx, accountID); err != nil {
		return stats, fmt.Errorf("failed to purge mailboxes: %w", err)
	}
	if err := s.rdb.PurgeCredentialsForAccount(ctx, accountID); err != nil {
		return stats, fmt.Errorf("failed to purge credentials: %w", err)
	}
	if err := s.rdb.PurgeAccount(ctx, accountID); err != nil {
		return stats, fmt.Errorf("failed to purge account: %w", err)
	}

	return stats, nil
}
