package db

import (
	"context"
	"fmt"
	"log"
	"time"
)

const CLEANUP_LOCK_NAME = "cleanup_worker"
const BATCH_PURGE_SIZE = 100
const LOCK_TIMEOUT = 30 * time.Second

// UserScopedObjectForCleanup represents a user-specific object that is a candidate for cleanup.
type UserScopedObjectForCleanup struct {
	AccountID   int64
	ContentHash string
	S3Domain    string
	S3Localpart string
}

func (d *Database) AcquireCleanupLock(ctx context.Context) (bool, error) {
	// Try to acquire lock by inserting a row, or updating if expired
	now := time.Now().UTC()
	expiresAt := now.Add(LOCK_TIMEOUT)

	result, err := d.GetWritePool().Exec(ctx, `
		INSERT INTO locks (lock_name, acquired_at, expires_at) 
		VALUES ($1, $2, $3)
		ON CONFLICT (lock_name) DO UPDATE SET
			acquired_at = $2,
			expires_at = $3
		WHERE locks.expires_at < $2
	`, CLEANUP_LOCK_NAME, now, expiresAt)

	if err != nil {
		return false, fmt.Errorf("failed to acquire lock: %w", err)
	}

	// Check if we successfully acquired the lock
	return result.RowsAffected() > 0, nil
}

func (d *Database) ReleaseCleanupLock(ctx context.Context) {
	_, _ = d.GetWritePool().Exec(ctx, `DELETE FROM locks WHERE lock_name = $1`, CLEANUP_LOCK_NAME)
}

// ExpungeOldMessages marks messages older than the specified duration as expunged
// This enables automatic cleanup of old messages based on age restriction
func (d *Database) ExpungeOldMessages(ctx context.Context, olderThan time.Duration) (int64, error) {
	threshold := time.Now().Add(-olderThan).UTC()

	result, err := d.GetWritePool().Exec(ctx, `
		UPDATE messages
		SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
		WHERE created_at < $1 AND expunged_at IS NULL
	`, threshold)

	if err != nil {
		return 0, fmt.Errorf("failed to expunge old messages: %w", err)
	}

	return result.RowsAffected(), nil
}

// GetUserScopedObjectsForCleanup identifies (AccountID, ContentHash) pairs where all messages
// for that user with that hash have been expunged for longer than the grace period.
func (d *Database) GetUserScopedObjectsForCleanup(ctx context.Context, olderThan time.Duration, limit int) ([]UserScopedObjectForCleanup, error) {
	threshold := time.Now().Add(-olderThan).UTC()
	rows, err := d.GetReadPool().Query(ctx, `
		SELECT account_id, s3_domain, s3_localpart, content_hash
		FROM messages
		GROUP BY account_id, s3_domain, s3_localpart, content_hash
		HAVING bool_and(uploaded = TRUE AND expunged_at IS NOT NULL AND expunged_at < $1)
		LIMIT $2;
	`, threshold, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query for user-scoped objects for cleanup: %w", err)
	}
	defer rows.Close()

	var result []UserScopedObjectForCleanup
	for rows.Next() {
		var candidate UserScopedObjectForCleanup
		if err := rows.Scan(&candidate.AccountID, &candidate.S3Domain, &candidate.S3Localpart, &candidate.ContentHash); err != nil {
			// Log and continue to process other rows
			log.Printf("failed to scan user-scoped object for cleanup: %v", err)
			continue
		}
		result = append(result, candidate)
	}
	return result, nil
}

// DeleteExpungedMessagesByS3KeyParts deletes all expunged message rows
// from the database that match the given S3 key components.
// It does NOT delete from message_contents, as the content may be shared.
func (d *Database) DeleteExpungedMessagesByS3KeyParts(ctx context.Context, accountID int64, s3Domain, s3Localpart, contentHash string) error {
	_, err := d.GetWritePool().Exec(ctx, `
		DELETE FROM messages
		WHERE account_id = $1 AND s3_domain = $2 AND s3_localpart = $3 AND content_hash = $4 AND expunged_at IS NOT NULL
	`, accountID, s3Domain, s3Localpart, contentHash)
	if err != nil {
		return fmt.Errorf("failed to delete expunged messages for account %d and S3 key parts (%s/%s/%s): %w", accountID, s3Domain, s3Localpart, contentHash, err)
	}
	return nil
}

// DeleteMessageByHashAndMailbox deletes message rows from the database that match
// the given AccountID, MailboxID, and ContentHash. This is a hard delete used
// by the importer for the --force-reimport option.
// It returns the number of messages deleted.
func (d *Database) DeleteMessageByHashAndMailbox(ctx context.Context, accountID int64, mailboxID int64, contentHash string) (int64, error) {
	tag, err := d.GetWritePool().Exec(ctx, `
		DELETE FROM messages
		WHERE account_id = $1 AND mailbox_id = $2 AND content_hash = $3
	`, accountID, mailboxID, contentHash)
	if err != nil {
		return 0, fmt.Errorf("failed to delete message for re-import (account: %d, mailbox: %d, hash: %s): %w", accountID, mailboxID, contentHash, err)
	}
	return tag.RowsAffected(), nil
}

// DeleteMessageContentByHash deletes a row from the message_contents table.
// This should only be called after confirming the hash is no longer in use by any message.
func (d *Database) DeleteMessageContentByHash(ctx context.Context, contentHash string) error {
	tag, err := d.GetWritePool().Exec(ctx, `DELETE FROM message_contents WHERE content_hash = $1`, contentHash)
	if err != nil {
		return fmt.Errorf("failed to delete from message_contents for hash %s: %w", contentHash, err)
	}
	if tag.RowsAffected() == 0 {
		log.Printf("[DB] no rows deleted from message_contents for hash %s (may have been already deleted or never created)", contentHash)
	}
	return nil
}

// CleanupFailedUploads deletes message rows and their corresponding pending_uploads
// that are older than the grace period and were never successfully uploaded to S3.
// This prevents orphaned message metadata from accumulating due to persistent upload failures.
func (d *Database) CleanupFailedUploads(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	threshold := time.Now().Add(-gracePeriod).UTC()
	tx, err := d.BeginTx(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction for failed upload cleanup: %w", err)
	}
	defer tx.Rollback(ctx)

	// Step 1: Delete messages that were never uploaded and are older than the grace period,
	// returning the identifiers of the deleted messages.
	rows, err := tx.Query(ctx, `
		DELETE FROM messages
		WHERE uploaded = FALSE AND created_at < $1
		RETURNING content_hash, account_id
	`, threshold)
	if err != nil {
		return 0, fmt.Errorf("failed to delete messages for failed uploads: %w", err)
	}

	var deletedMessagesCount int64
	var contentHashes []string
	var accountIDs []int64

	for rows.Next() {
		var hash string
		var accountID int64
		if err := rows.Scan(&hash, &accountID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("failed to scan deleted message info: %w", err)
		}
		contentHashes = append(contentHashes, hash)
		accountIDs = append(accountIDs, accountID)
		deletedMessagesCount++
	}
	rows.Close()

	if deletedMessagesCount > 0 {
		// Step 2: Delete the corresponding entries from pending_uploads in a single batch.
		_, err = tx.Exec(ctx, `
			DELETE FROM pending_uploads pu
			USING unnest($1::text[], $2::bigint[]) AS d(content_hash, account_id)
			WHERE pu.content_hash = d.content_hash AND pu.account_id = d.account_id
		`, contentHashes, accountIDs)
		if err != nil {
			return 0, fmt.Errorf("failed to delete from pending_uploads: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("failed to commit failed upload cleanup: %w", err)
	}

	return deletedMessagesCount, nil
}

// CleanupOldMessageContents deletes message_contents rows for messages older than the retention period.
// This is based on the newest (MAX) sent_date of all messages that reference a given content_hash.
func (d *Database) CleanupOldMessageContents(ctx context.Context, retentionPeriod time.Duration) (int64, error) {
	threshold := time.Now().Add(-retentionPeriod).UTC()

	// Use DELETE ... USING, which is generally more efficient than a subquery with IN.
	result, err := d.GetWritePool().Exec(ctx, `
		DELETE FROM message_contents mc
		USING (
			SELECT content_hash
			FROM messages
			GROUP BY content_hash
			HAVING MAX(sent_date) < $1
		) AS to_delete
		WHERE mc.content_hash = to_delete.content_hash
	`, threshold)

	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old message contents: %w", err)
	}

	return result.RowsAffected(), nil
}

// GetUnusedContentHashes finds content_hash values in message_contents that are no longer referenced
// by any message row at all. These are candidates for global cleanup.
func (d *Database) GetUnusedContentHashes(ctx context.Context, limit int) ([]string, error) {
	rows, err := d.GetReadPool().Query(ctx, `
		SELECT mc.content_hash
		FROM message_contents mc
		WHERE NOT EXISTS (
			SELECT 1
			FROM messages m
			WHERE m.content_hash = mc.content_hash
		)
		LIMIT $1;
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query for unused content hashes: %w", err)
	}
	defer rows.Close()

	var result []string
	for rows.Next() {
		var contentHash string
		if err := rows.Scan(&contentHash); err != nil {
			log.Printf("failed to scan unused content hash: %v", err)
			continue
		}
		result = append(result, contentHash)
	}
	return result, nil
}

// CleanupSoftDeletedAccounts permanently deletes accounts that have been soft-deleted
// for longer than the grace period
func (d *Database) CleanupSoftDeletedAccounts(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	threshold := time.Now().Add(-gracePeriod).UTC()

	// Get accounts that have been soft-deleted longer than the grace period
	rows, err := d.GetReadPool().Query(ctx, `
		SELECT id 
		FROM accounts 
		WHERE deleted_at IS NOT NULL AND deleted_at < $1
		ORDER BY deleted_at ASC
		LIMIT 50
	`, threshold)
	if err != nil {
		return 0, fmt.Errorf("failed to query soft-deleted accounts: %w", err)
	}
	defer rows.Close()

	var accountsToDelete []int64
	for rows.Next() {
		var accountID int64
		if err := rows.Scan(&accountID); err != nil {
			log.Printf("failed to scan account ID: %v", err)
			continue
		}
		accountsToDelete = append(accountsToDelete, accountID)
	}

	if len(accountsToDelete) == 0 {
		return 0, nil
	}

	var totalDeleted int64
	for _, accountID := range accountsToDelete {
		if err := d.HardDeleteAccount(ctx, accountID); err != nil {
			log.Printf("failed to hard delete account %d: %v", accountID, err)
			continue
		}
		totalDeleted++
	}

	if totalDeleted > 0 {
		log.Printf("cleaned up %d soft-deleted accounts that exceeded grace period", totalDeleted)
	}

	return totalDeleted, nil
}

// GetDanglingAccountsForFinalDeletion finds accounts that are marked as deleted and have no
// messages left. Once all messages (and their corresponding S3 objects) are cleaned up,
// the account's master record is safe to be permanently removed.
func (d *Database) GetDanglingAccountsForFinalDeletion(ctx context.Context, limit int) ([]int64, error) {
	rows, err := d.GetReadPool().Query(ctx, `
		SELECT a.id
		FROM accounts a
		WHERE a.deleted_at IS NOT NULL
		AND NOT EXISTS (SELECT 1 FROM messages WHERE account_id = a.id)
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query for dangling accounts: %w", err)
	}
	defer rows.Close()

	var accountIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			// Log and continue to process other rows
			log.Printf("failed to scan dangling account id: %v", err)
			continue
		}
		accountIDs = append(accountIDs, id)
	}
	return accountIDs, nil
}

// FinalizeAccountDeletion permanently deletes an account and its credentials.
// This should only be called on a dangling account that has no other dependencies.
// The ON DELETE RESTRICT constraint on the messages table provides a final safety check.
func (d *Database) FinalizeAccountDeletion(ctx context.Context, accountID int64) error {
	tx, err := d.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for final account deletion: %w", err)
	}
	defer tx.Rollback(ctx)

	// First, delete credentials associated with the account.
	_, err = tx.Exec(ctx, "DELETE FROM credentials WHERE account_id = $1", accountID)
	if err != nil {
		return fmt.Errorf("failed to delete credentials during finalization for account %d: %w", accountID, err)
	}

	// Finally, delete the account itself.
	result, err := tx.Exec(ctx, "DELETE FROM accounts WHERE id = $1", accountID)
	if err != nil {
		// The ON DELETE RESTRICT on messages should prevent this if messages still exist.
		return fmt.Errorf("failed to finalize deletion of account %d: %w", accountID, err)
	}

	if result.RowsAffected() == 0 {
		// This could happen in a race condition if another cleaner instance just deleted it.
		// Not a critical error, but we can log it.
		log.Printf("FinalizeAccountDeletion for account %d affected 0 rows. It may have already been deleted.", accountID)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit final account deletion transaction for account %d: %w", accountID, err)
	}

	return nil
}

// CleanupOldAuthAttempts removes authentication attempts older than the specified duration
func (d *Database) CleanupOldAuthAttempts(ctx context.Context, maxAge time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-maxAge)

	query := `DELETE FROM auth_attempts WHERE attempted_at < $1`

	result, err := d.GetWritePool().Exec(ctx, query, cutoffTime)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old auth attempts: %w", err)
	}

	rowsAffected := result.RowsAffected()
	return rowsAffected, nil
}

// CleanupOldHealthStatuses removes health status records that haven't been updated
// for longer than the specified retention period. This is useful for removing
// records of decommissioned servers.
func (d *Database) CleanupOldHealthStatuses(ctx context.Context, retention time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-retention)

	query := `DELETE FROM health_status WHERE updated_at < $1`

	result, err := d.GetWritePool().Exec(ctx, query, cutoffTime)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old health statuses: %w", err)
	}

	return result.RowsAffected(), nil
}
