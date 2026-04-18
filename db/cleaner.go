package db

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/logger"
)

const BATCH_PURGE_SIZE = 1000

// Advisory lock ID for cleanup worker coordination
// Computed as: hash("sora_cleanup_worker") & 0x7FFFFFFF to ensure positive int32
const CLEANUP_ADVISORY_LOCK_ID = 1876543210

// UserScopedObjectForCleanup represents a user-specific object that is a candidate for cleanup.
type UserScopedObjectForCleanup struct {
	AccountID   int64
	ContentHash string
	S3Domain    string
	S3Localpart string
}

// AcquireCleanupLock attempts to acquire a transaction-scoped advisory lock for the cleanup worker.
// Returns true if lock was acquired, false if another instance holds it.
// The lock is automatically released when the transaction commits or rolls back.
// NOTE: Uses transaction-scoped lock (pg_advisory_xact_lock) to avoid connection pool issues.
func (d *Database) AcquireCleanupLock(ctx context.Context, tx pgx.Tx) (bool, error) {
	var acquired bool
	err := tx.QueryRow(ctx,
		"SELECT pg_try_advisory_xact_lock($1)",
		CLEANUP_ADVISORY_LOCK_ID).Scan(&acquired)
	if err != nil {
		return false, fmt.Errorf("failed to acquire cleanup advisory lock: %w", err)
	}
	return acquired, nil
}

// ReleaseCleanupLock is a no-op for transaction-scoped advisory locks.
// The lock is automatically released when the transaction commits or rolls back.
// Kept for API compatibility.
func (d *Database) ReleaseCleanupLock(ctx context.Context, tx pgx.Tx) error {
	// Transaction-scoped locks (pg_advisory_xact_lock) are automatically released
	// on COMMIT or ROLLBACK, so we don't need to explicitly unlock.
	return nil
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
//
// Uses a bounded scan-window approach: each batch scans a fixed number of rows from
// idx_messages_cleanup_grouping. This ensures predictable execution time and avoids
// timeout errors when there are many expunged rows but few matching the NOT EXISTS criteria.
func (d *Database) GetUserScopedObjectsForCleanup(ctx context.Context, olderThan time.Duration, limit int) ([]UserScopedObjectForCleanup, error) {
	const scanWindowSize = 5000
	const maxBatches = 200                  // Upper bound: scan up to 1M groups total
	const maxRunDuration = 25 * time.Second // Wall-clock cap

	var allCandidates []UserScopedObjectForCleanup

	// Tuple cursor for pagination through the index
	var lastAccountID int64 = -1
	var lastDomain string = ""
	var lastLocalpart string = ""
	var lastHash string = ""

	runDeadline := time.Now().Add(maxRunDuration)
	threshold := time.Now().Add(-olderThan).UTC()

	for batch := 0; batch < maxBatches && len(allCandidates) < limit; batch++ {
		// Respect the per-run time cap
		if time.Now().After(runDeadline) {
			logger.Info("GetUserScopedObjectsForCleanup: reached time limit, returning partial results",
				"found", len(allCandidates), "requested", limit, "batches", batch)
			break
		}

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		query := `
			WITH RECURSIVE scan_window AS (
				(
					SELECT m.account_id, m.s3_domain, m.s3_localpart, m.content_hash
					FROM messages m
					WHERE m.uploaded = TRUE AND m.expunged_at IS NOT NULL
					  AND (m.account_id, m.s3_domain, m.s3_localpart, m.content_hash) > ($1, $2, $3, $4)
					ORDER BY m.account_id, m.s3_domain, m.s3_localpart, m.content_hash
					LIMIT 1
				)
				UNION ALL
				SELECT m.account_id, m.s3_domain, m.s3_localpart, m.content_hash
				FROM scan_window sw
				CROSS JOIN LATERAL (
					SELECT m2.account_id, m2.s3_domain, m2.s3_localpart, m2.content_hash
					FROM messages m2
					WHERE m2.uploaded = TRUE AND m2.expunged_at IS NOT NULL
					  AND (m2.account_id, m2.s3_domain, m2.s3_localpart, m2.content_hash) > (sw.account_id, sw.s3_domain, sw.s3_localpart, sw.content_hash)
					ORDER BY m2.account_id, m2.s3_domain, m2.s3_localpart, m2.content_hash
					LIMIT 1
				) m
			)
			SELECT 
				sw.account_id, sw.s3_domain, sw.s3_localpart, sw.content_hash,
				(active.found IS NULL AND recent.found IS NULL) as is_orphan
			FROM (SELECT * FROM scan_window LIMIT $5) sw
			LEFT JOIN LATERAL (
				SELECT 1 as found FROM messages m_active
				WHERE m_active.account_id = sw.account_id
				  AND m_active.content_hash = sw.content_hash
				  AND m_active.expunged_at IS NULL
				LIMIT 1
			) active ON true
			LEFT JOIN LATERAL (
				SELECT 1 as found FROM messages m_recent
				WHERE m_recent.account_id = sw.account_id
				  AND m_recent.content_hash = sw.content_hash
				  AND m_recent.expunged_at >= $6
				LIMIT 1
			) recent ON true
			ORDER BY sw.account_id, sw.s3_domain, sw.s3_localpart, sw.content_hash
		`

		rows, err := d.GetReadPool().Query(ctx, query, lastAccountID, lastDomain, lastLocalpart, lastHash, scanWindowSize, threshold)
		if err != nil {
			return nil, fmt.Errorf("failed to query user-scoped objects for cleanup: %w", err)
		}

		var batchCandidates []UserScopedObjectForCleanup
		var rowsProcessed int

		for rows.Next() {
			rowsProcessed++
			var candidate UserScopedObjectForCleanup
			var isOrphan bool
			if err := rows.Scan(&candidate.AccountID, &candidate.S3Domain, &candidate.S3Localpart, &candidate.ContentHash, &isOrphan); err != nil {
				rows.Close()
				return nil, fmt.Errorf("failed to scan user-scoped object for cleanup: %w", err)
			}

			// Update cursor
			lastAccountID = candidate.AccountID
			lastDomain = candidate.S3Domain
			lastLocalpart = candidate.S3Localpart
			lastHash = candidate.ContentHash

			if isOrphan {
				batchCandidates = append(batchCandidates, candidate)
			}
		}
		rows.Close()

		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating user-scoped objects: %w", err)
		}

		// If we processed fewer rows than scanWindowSize, we have reached the end
		if rowsProcessed == 0 {
			break
		}

		if len(batchCandidates) > 0 {
			remaining := limit - len(allCandidates)
			if len(batchCandidates) > remaining {
				batchCandidates = batchCandidates[:remaining]
			}
			allCandidates = append(allCandidates, batchCandidates...)
		}

		// Short sleep between batches to reduce DB pressure
		time.Sleep(10 * time.Millisecond)
	}

	return allCandidates, nil
}

// DeleteExpungedMessagesByS3KeyPartsBatch deletes all expunged message rows
// from the database that match the given batches of S3 key components.
// It does NOT delete from messages_fts, as the content may be shared.
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

// PruneOldMessageVectors deletes messages_fts rows whose fts_retention has expired.
// Each row holds the FTS search vector (text_body_tsv).
//
// The DELETE uses a CTE with LIMIT to cap each invocation at maxPruneRows rows,
// preventing long-held locks and WAL bloat if fts_retention is shortened dramatically.
// The cleanup worker calls this periodically; remaining rows are pruned on the next cycle.
//
// The range scan uses the idx_messages_fts_sent_date partial index (WHERE sent_date
// IS NOT NULL), so pre-existing rows with NULL sent_date are never selected.
func (d *Database) PruneOldMessageVectors(ctx context.Context, tx pgx.Tx, retention time.Duration) (int64, error) {
	const maxPruneRows = 1_000

	tag, err := tx.Exec(ctx, `
		WITH expired AS (
			SELECT content_hash FROM messages_fts
			WHERE sent_date < (now() - $1::interval)
			ORDER BY sent_date
			FOR UPDATE SKIP LOCKED
			LIMIT $2
		)
		DELETE FROM messages_fts
		WHERE content_hash IN (SELECT content_hash FROM expired)
	`, retention, maxPruneRows)
	if err != nil {
		return 0, fmt.Errorf("failed to prune old message vectors: %w", err)
	}

	return tag.RowsAffected(), nil
}

// GetUnusedFTSHashes finds content_hash values in messages_fts that are no longer referenced
// by any message row at all. These are candidates for early cleanup even before TTL expires.
//
// Uses a bounded scan-window approach to limit query duration.
func (d *Database) GetUnusedFTSHashes(ctx context.Context, limit int) ([]string, error) {
	const scanWindowSize = 5000
	const maxBatches = 200
	const maxRunDuration = 30 * time.Second

	var allHashes []string
	var lastHash string
	runDeadline := time.Now().Add(maxRunDuration)

	for batch := 0; batch < maxBatches && len(allHashes) < limit; batch++ {
		if time.Now().After(runDeadline) {
			logger.Info("GetUnusedFTSHashes: reached time limit, returning partial results",
				"found", len(allHashes), "requested", limit, "batches", batch)
			break
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		query := `
			WITH scan_window AS (
				SELECT mc.content_hash
				FROM messages_fts mc
				WHERE mc.content_hash > $1
				ORDER BY mc.content_hash
				LIMIT $2
			)
			SELECT
				COALESCE((SELECT MAX(content_hash) FROM scan_window), '') AS window_end,
				ARRAY(
					SELECT sw.content_hash
					FROM scan_window sw
					LEFT JOIN LATERAL (
						SELECT 1 as found
						FROM messages m
						WHERE m.content_hash = sw.content_hash
						LIMIT 1
					) active_msg ON true
					WHERE active_msg.found IS NULL
				) AS orphan_hashes
		`

		var windowEnd string
		var batchHashes []string
		err := d.GetReadPool().QueryRow(ctx, query, lastHash, scanWindowSize).Scan(&windowEnd, &batchHashes)
		if err != nil {
			return nil, fmt.Errorf("failed to query unused FTS hashes: %w", err)
		}

		if windowEnd == "" {
			break
		}

		lastHash = windowEnd

		if len(batchHashes) > 0 {
			remaining := limit - len(allHashes)
			if len(batchHashes) > remaining {
				batchHashes = batchHashes[:remaining]
			}
			allHashes = append(allHashes, batchHashes...)
		}

		time.Sleep(10 * time.Millisecond)
	}

	return allHashes, nil
}

// DeleteMessagesFTSByHashBatch deletes multiple rows from the messages_fts table.
func (d *Database) DeleteMessagesFTSByHashBatch(ctx context.Context, tx pgx.Tx, contentHashes []string) (int64, error) {
	if len(contentHashes) == 0 {
		return 0, nil
	}
	tag, err := tx.Exec(ctx, `DELETE FROM messages_fts WHERE content_hash = ANY($1)`, contentHashes)
	if err != nil {
		return 0, fmt.Errorf("failed to batch delete from messages_fts: %w", err)
	}
	return tag.RowsAffected(), nil
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
		logger.Error("failed to hard delete account batch", "err", err)
		return 0, err
	}

	totalDeleted := int64(len(accountsToDelete))

	if totalDeleted > 0 {
		logger.Info("cleaned up soft-deleted accounts that exceeded grace period", "count", totalDeleted)
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

// GetMessagesForMailboxAndChildren retrieves all messages for a mailbox and its children
// This is used by the admin tool for immediate purging of messages
func (d *Database) GetMessagesForMailboxAndChildren(ctx context.Context, accountID int64, mailboxID int64, mailboxPath string) ([]Message, error) {
	query := `
		SELECT
			m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart,
			m.uploaded, ms.flags, ms.custom_flags, m.internal_date, m.size,
			m.created_modseq, ms.updated_modseq, m.expunged_modseq, 0 as seqnum,
			ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.account_id = $1
		  AND (mb.id = $2 OR mb.path LIKE $3 || '%')
		ORDER BY m.id
	`

	rows, err := d.GetReadPool().Query(ctx, query, accountID, mailboxID, mailboxPath)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages for mailbox and children: %w", err)
	}
	defer rows.Close()

	return scanMessages(rows, false)
}

// PurgeMessagesByIDs permanently deletes messages by their IDs
// This is a hard delete used by the admin tool for immediate purging
func (d *Database) PurgeMessagesByIDs(ctx context.Context, messageIDs []int64) (int64, error) {
	if len(messageIDs) == 0 {
		return 0, nil
	}

	tx, err := d.GetWritePool().Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	result, err := tx.Exec(ctx, `DELETE FROM messages WHERE id = ANY($1)`, messageIDs)
	if err != nil {
		return 0, fmt.Errorf("failed to purge messages: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("failed to commit purge transaction: %w", err)
	}

	return result.RowsAffected(), nil
}

// GetMessagesForAccount retrieves all messages for an account
// This is used by the admin tool to identify S3 objects before purging
// Returns only the minimal fields needed to construct S3 keys
func (d *Database) GetMessagesForAccount(ctx context.Context, accountID int64) ([]Message, error) {
	query := `
		SELECT
			m.id, m.account_id, m.uid, m.mailbox_id, m.content_hash, m.s3_domain, m.s3_localpart,
			m.uploaded, ms.flags, ms.custom_flags, m.internal_date, m.size,
			m.created_modseq, ms.updated_modseq, m.expunged_modseq, 0 as seqnum,
			ms.flags_changed_at, m.subject, m.sent_date, m.message_id, m.in_reply_to, m.recipients_json
		FROM messages m
		LEFT JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.account_id = $1
		ORDER BY m.id
	`

	rows, err := d.GetReadPool().Query(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to query messages for account: %w", err)
	}
	defer rows.Close()

	return scanMessages(rows, false)
}

// ExpungeAllMessagesForAccount marks all messages for an account as expunged
// This is the first step in account deletion - marks messages for cleanup
// The actual deletion from S3 and DB happens via GetUserScopedObjectsForCleanup
func (d *Database) ExpungeAllMessagesForAccount(ctx context.Context, accountID int64) (int64, error) {
	tx, err := d.GetWritePool().Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	result, err := tx.Exec(ctx, `
		UPDATE messages
		SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
		WHERE account_id = $1 AND expunged_at IS NULL
	`, accountID)
	if err != nil {
		return 0, fmt.Errorf("failed to expunge messages: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("failed to commit expunge transaction: %w", err)
	}

	return result.RowsAffected(), nil
}

// GetUserScopedObjectsForAccount retrieves all expunged messages for a specific account
// Use gracePeriod=0 for immediate cleanup (admin purge), >0 for normal cleanup worker
//
// SAFETY: This function is account-isolated by design:
// - Filters by account_id in WHERE clause
// - Returns only S3 objects for messages belonging to the specified account
// - Safe to delete returned S3 objects without affecting other accounts because:
//  1. Email addresses are globally unique (UNIQUE INDEX on credentials.address)
//  2. S3 keys = <s3_domain>/<s3_localpart>/<content_hash> = <email_domain>/<email_localpart>/<hash>
//  3. Different accounts → different email addresses → different S3 paths
//  4. Even if same content_hash, different email → different S3 object
func (d *Database) GetUserScopedObjectsForAccount(ctx context.Context, accountID int64, gracePeriod time.Duration, limit int) ([]UserScopedObjectForCleanup, error) {
	threshold := time.Now().Add(-gracePeriod).UTC()
	rows, err := d.GetReadPool().Query(ctx, `
		SELECT account_id, s3_domain, s3_localpart, content_hash
		FROM messages
		WHERE account_id = $1
		GROUP BY account_id, s3_domain, s3_localpart, content_hash
		HAVING bool_and(uploaded = TRUE AND expunged_at IS NOT NULL AND expunged_at < $2)
		LIMIT $3;
	`, accountID, threshold, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query for user-scoped objects for account cleanup: %w", err)
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

// GetAllUploadedObjectsForAccount retrieves ALL uploaded S3 objects for a specific account
// regardless of expunge status. Used for account purging when messages might already be deleted from DB.
//
// SAFETY: This function is account-isolated by design (same guarantees as GetUserScopedObjectsForAccount)
func (d *Database) GetAllUploadedObjectsForAccount(ctx context.Context, accountID int64, limit int) ([]UserScopedObjectForCleanup, error) {
	rows, err := d.GetReadPool().Query(ctx, `
		SELECT account_id, s3_domain, s3_localpart, content_hash
		FROM messages
		WHERE account_id = $1 AND uploaded = TRUE
		GROUP BY account_id, s3_domain, s3_localpart, content_hash
		LIMIT $2;
	`, accountID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query for all uploaded objects for account: %w", err)
	}
	defer rows.Close()

	var result []UserScopedObjectForCleanup
	for rows.Next() {
		var candidate UserScopedObjectForCleanup
		if err := rows.Scan(&candidate.AccountID, &candidate.S3Domain, &candidate.S3Localpart, &candidate.ContentHash); err != nil {
			return nil, fmt.Errorf("failed to scan uploaded object for cleanup: %w", err)
		}
		result = append(result, candidate)
	}
	return result, rows.Err()
}

// PurgeMailboxesForAccount permanently deletes all mailboxes for an account
// This is a hard delete used by the admin tool for immediate account purging
func (d *Database) PurgeMailboxesForAccount(ctx context.Context, accountID int64) error {
	tx, err := d.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `DELETE FROM mailboxes WHERE account_id = $1`, accountID)
	if err != nil {
		return fmt.Errorf("failed to purge mailboxes: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit purge transaction: %w", err)
	}

	return nil
}

// PurgeCredentialsForAccount permanently deletes all credentials for an account
// This is a hard delete used by the admin tool for immediate account purging
func (d *Database) PurgeCredentialsForAccount(ctx context.Context, accountID int64) error {
	tx, err := d.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `DELETE FROM credentials WHERE account_id = $1`, accountID)
	if err != nil {
		return fmt.Errorf("failed to purge credentials: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit purge transaction: %w", err)
	}

	return nil
}

// PurgeAccount permanently deletes an account
// This is a hard delete used by the admin tool for immediate account purging
// Note: All associated data (messages, mailboxes, credentials) should be deleted first
func (d *Database) PurgeAccount(ctx context.Context, accountID int64) error {
	tx, err := d.GetWritePool().Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, accountID)
	if err != nil {
		return fmt.Errorf("failed to purge account: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit purge transaction: %w", err)
	}

	return nil
}
