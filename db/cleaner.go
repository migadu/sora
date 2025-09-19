package db

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
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

func (d *Database) AcquireCleanupLock(ctx context.Context, tx pgx.Tx) (bool, error) {
	// Try to acquire lock by inserting a row, or updating if expired
	now := time.Now().UTC()
	expiresAt := now.Add(LOCK_TIMEOUT)

	result, err := tx.Exec(ctx, `
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

func (d *Database) ReleaseCleanupLock(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `DELETE FROM locks WHERE lock_name = $1`, CLEANUP_LOCK_NAME)
	return err
}

// ExpungeOldMessages marks messages older than the specified duration as expunged
// This enables automatic cleanup of old messages based on age restriction
func (d *Database) ExpungeOldMessages(ctx context.Context, tx pgx.Tx, olderThan time.Duration) (int64, error) {
	threshold := time.Now().Add(-olderThan).UTC()

	result, err := tx.Exec(ctx, `
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
			return nil, fmt.Errorf("failed to scan user-scoped object for cleanup: %w", err)
		}
		result = append(result, candidate)
	}
	return result, rows.Err()
}

// DeleteExpungedMessagesByS3KeyPartsBatch deletes all expunged message rows
// from the database that match the given batches of S3 key components.
// It does NOT delete from message_contents, as the content may be shared.
func (d *Database) DeleteExpungedMessagesByS3KeyPartsBatch(ctx context.Context, tx pgx.Tx, candidates []UserScopedObjectForCleanup) (int64, error) {
	if len(candidates) == 0 {
		return 0, nil
	}

	accountIDs := make([]int64, len(candidates))
	s3Domains := make([]string, len(candidates))
	s3Localparts := make([]string, len(candidates))
	contentHashes := make([]string, len(candidates))

	for i, c := range candidates {
		accountIDs[i] = c.AccountID
		s3Domains[i] = c.S3Domain
		s3Localparts[i] = c.S3Localpart
		contentHashes[i] = c.ContentHash
	}

	tag, err := tx.Exec(ctx, `
		DELETE FROM messages m
		USING unnest($1::bigint[], $2::text[], $3::text[], $4::text[]) AS d(account_id, s3_domain, s3_localpart, content_hash)
		WHERE m.account_id = d.account_id
		  AND m.s3_domain = d.s3_domain
		  AND m.s3_localpart = d.s3_localpart
		  AND m.content_hash = d.content_hash
		  AND m.expunged_at IS NOT NULL
	`, accountIDs, s3Domains, s3Localparts, contentHashes)
	if err != nil {
		return 0, fmt.Errorf("failed to batch delete expunged messages: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteMessageByHashAndMailbox deletes message rows from the database that match
// the given AccountID, MailboxID, and ContentHash. This is a hard delete used
// by the importer for the --force-reimport option.
// It returns the number of messages deleted.
func (d *Database) DeleteMessageByHashAndMailbox(ctx context.Context, tx pgx.Tx, accountID int64, mailboxID int64, contentHash string) (int64, error) {
	tag, err := tx.Exec(ctx, `
		DELETE FROM messages
		WHERE account_id = $1 AND mailbox_id = $2 AND content_hash = $3
	`, accountID, mailboxID, contentHash)
	if err != nil {
		return 0, fmt.Errorf("failed to delete message for re-import (account: %d, mailbox: %d, hash: %s): %w", accountID, mailboxID, contentHash, err)
	}
	return tag.RowsAffected(), nil
}

// DeleteMessageContentsByHashBatch deletes multiple rows from the message_contents table.
// This should only be called after confirming the hashes are no longer in use by any message.
func (d *Database) DeleteMessageContentsByHashBatch(ctx context.Context, tx pgx.Tx, contentHashes []string) (int64, error) {
	if len(contentHashes) == 0 {
		return 0, nil
	}
	tag, err := tx.Exec(ctx, `DELETE FROM message_contents WHERE content_hash = ANY($1)`, contentHashes)
	if err != nil {
		return 0, fmt.Errorf("failed to batch delete from message_contents: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CleanupFailedUploads deletes message rows and their corresponding pending_uploads
// that are older than the grace period and were never successfully uploaded to S3.
// This prevents orphaned message metadata from accumulating due to persistent upload failures.
func (d *Database) CleanupFailedUploads(ctx context.Context, tx pgx.Tx, gracePeriod time.Duration) (int64, error) {
	threshold := time.Now().Add(-gracePeriod).UTC()

	// This single query uses a Common Table Expression (CTE) to perform both deletions
	// in one atomic operation, which is more efficient than two separate queries.
	// 1. The `deleted_messages` CTE deletes old, non-uploaded messages and returns their keys.
	// 2. The `deleted_pending` CTE then uses these keys to remove the corresponding
	//    entries from `pending_uploads`.
	// The final SELECT returns the count of messages that were deleted.
	query := `
		WITH deleted_messages AS (
			DELETE FROM messages
			WHERE uploaded = FALSE AND created_at < $1
			RETURNING content_hash, account_id
		),
		deleted_pending AS (
			DELETE FROM pending_uploads pu
			WHERE (pu.content_hash, pu.account_id) IN (SELECT content_hash, account_id FROM deleted_messages)
		)
		SELECT count(*) FROM deleted_messages
	`

	var deletedCount int64
	err := tx.QueryRow(ctx, query, threshold).Scan(&deletedCount)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup failed uploads: %w", err)
	}

	return deletedCount, nil
}

// PruneOldMessageBodies sets the text_body to NULL for message contents
// where all associated non-expunged messages are older than the given retention period.
// This saves storage while preserving the text_body_tsv for full-text search.
func (d *Database) PruneOldMessageBodies(ctx context.Context, tx pgx.Tx, retention time.Duration) (int64, error) {
	// This query is optimized to use a NOT EXISTS clause, which is generally more
	// efficient than a subquery with GROUP BY and MAX(). It finds content hashes
	// that have not been pruned yet (text_body IS NOT NULL) and for which no
	// active, recent message exists.
	query := `
		UPDATE message_contents
		SET 
			text_body = NULL,
			updated_at = now()
		WHERE content_hash IN (
			SELECT content_hash
			FROM message_contents
			WHERE text_body IS NOT NULL
			  AND NOT EXISTS (
				SELECT 1 FROM messages m
				WHERE m.content_hash = message_contents.content_hash
				  AND m.expunged_at IS NULL
				  AND m.sent_date >= (now() - $1)
			  )
		)
	`
	tag, err := tx.Exec(ctx, query, retention)
	if err != nil {
		return 0, fmt.Errorf("failed to prune old message bodies: %w", err)
	}
	return tag.RowsAffected(), nil
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
			return nil, fmt.Errorf("failed to scan unused content hash: %w", err)
		}
		result = append(result, contentHash)
	}
	return result, rows.Err()
}

// CleanupSoftDeletedAccounts permanently deletes accounts that have been soft-deleted
// for longer than the grace period
func (d *Database) CleanupSoftDeletedAccounts(ctx context.Context, tx pgx.Tx, gracePeriod time.Duration) (int64, error) {
	threshold := time.Now().Add(-gracePeriod).UTC()

	// Get accounts that have been soft-deleted longer than the grace period
	rows, err := tx.Query(ctx, `
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
			return 0, fmt.Errorf("failed to scan account ID for cleanup: %w", err)
		}
		accountsToDelete = append(accountsToDelete, accountID)
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("error iterating soft-deleted accounts: %w", err)
	}

	if len(accountsToDelete) == 0 {
		return 0, nil
	}

	// Perform the first stage of deletion in a single batch transaction
	if err := d.HardDeleteAccounts(ctx, tx, accountsToDelete); err != nil {
		// If the batch fails, we can't be sure which accounts were processed.
		// Log the error and return. The next run will pick them up.
		log.Printf("failed to hard delete account batch: %v", err)
		return 0, err
	}

	totalDeleted := int64(len(accountsToDelete))

	if totalDeleted > 0 {
		log.Printf("cleaned up %d soft-deleted accounts that exceeded grace period", totalDeleted)
	}

	return totalDeleted, nil
}

// HardDeleteAccounts performs the first stage of permanent deletion for a batch of accounts.
// It expunges all their messages and deletes associated data like mailboxes, sieve scripts, etc.
// It does NOT delete the account or credential rows themselves, as they are needed for S3 cleanup.
func (d *Database) HardDeleteAccounts(ctx context.Context, tx pgx.Tx, accountIDs []int64) error {
	if len(accountIDs) == 0 {
		return nil
	}

	// Get all mailbox IDs for the accounts being deleted to lock them in a consistent order.
	var mailboxIDs []int64
	rows, err := tx.Query(ctx, "SELECT id FROM mailboxes WHERE account_id = ANY($1)", accountIDs)
	if err != nil {
		return fmt.Errorf("failed to query mailbox IDs for locking: %w", err)
	}
	mailboxIDs, err = pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return fmt.Errorf("failed to collect mailbox IDs for locking: %w", err)
	}

	// Sort the IDs to ensure a consistent lock acquisition order.
	sort.Slice(mailboxIDs, func(i, j int) bool { return mailboxIDs[i] < mailboxIDs[j] })

	// Acquire locks in a deterministic order.
	if len(mailboxIDs) > 0 {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(id) FROM unnest($1::bigint[]) AS id", mailboxIDs); err != nil {
			return fmt.Errorf("failed to acquire locks for account deletion: %w", err)
		}
	}

	// Use = ANY($1) for efficient batch operations
	batchOps := []struct {
		tableName string
		query     string
	}{
		{"server_affinity", "DELETE FROM server_affinity WHERE account_id = ANY($1)"},
		{"active_connections", "DELETE FROM active_connections WHERE account_id = ANY($1)"},
		{"vacation_responses", "DELETE FROM vacation_responses WHERE account_id = ANY($1)"},
		{"sieve_scripts", "DELETE FROM sieve_scripts WHERE account_id = ANY($1)"},
		{"pending_uploads", "DELETE FROM pending_uploads WHERE account_id = ANY($1)"},
		{"mailboxes", "DELETE FROM mailboxes WHERE account_id = ANY($1)"},
	}

	for _, op := range batchOps {
		if _, err := tx.Exec(ctx, op.query, accountIDs); err != nil {
			return fmt.Errorf("failed to batch delete from %s: %w", op.tableName, err)
		}
	}

	// Mark all messages for the deleted accounts as expunged.
	// This signals the next phase of the cleanup worker to remove the S3 objects.
	_, err = tx.Exec(ctx, `
		UPDATE messages 
		SET expunged_at = now(), expunged_modseq = nextval('messages_modseq')
		WHERE account_id = ANY($1) AND expunged_at IS NULL
	`, accountIDs)
	if err != nil {
		return fmt.Errorf("failed to expunge messages for batch deletion: %w", err)
	}

	return nil
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
			return nil, fmt.Errorf("failed to scan dangling account id: %w", err)
		}
		accountIDs = append(accountIDs, id)
	}
	return accountIDs, rows.Err()
}

// FinalizeAccountDeletions permanently deletes a batch of accounts and their credentials.
// This should only be called on dangling accounts that have no other dependencies.
func (d *Database) FinalizeAccountDeletions(ctx context.Context, tx pgx.Tx, accountIDs []int64) (int64, error) {
	if len(accountIDs) == 0 {
		return 0, nil
	}

	// First, delete credentials associated with the accounts.
	_, err := tx.Exec(ctx, "DELETE FROM credentials WHERE account_id = ANY($1)", accountIDs)
	if err != nil {
		return 0, fmt.Errorf("failed to batch delete credentials during finalization: %w", err)
	}

	// Finally, delete the accounts themselves.
	// The ON DELETE RESTRICT on messages provides a final safety check.
	result, err := tx.Exec(ctx, "DELETE FROM accounts WHERE id = ANY($1)", accountIDs)
	if err != nil {
		return 0, fmt.Errorf("failed to finalize batch deletion of accounts: %w", err)
	}

	return result.RowsAffected(), nil
}

// CleanupOldAuthAttempts removes authentication attempts older than the specified duration
func (d *Database) CleanupOldAuthAttempts(ctx context.Context, tx pgx.Tx, maxAge time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-maxAge)

	query := `DELETE FROM auth_attempts WHERE attempted_at < $1`

	result, err := tx.Exec(ctx, query, cutoffTime)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old auth attempts: %w", err)
	}

	rowsAffected := result.RowsAffected()
	return rowsAffected, nil
}

// CleanupOldHealthStatuses removes health status records that haven't been updated
// for longer than the specified retention period. This is useful for removing
// records of decommissioned servers.
func (d *Database) CleanupOldHealthStatuses(ctx context.Context, tx pgx.Tx, retention time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-retention)

	query := `DELETE FROM health_status WHERE updated_at < $1`

	result, err := tx.Exec(ctx, query, cutoffTime)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup old health statuses: %w", err)
	}

	return result.RowsAffected(), nil
}
