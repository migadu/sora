package db

import (
	"context"
	"fmt"
	"log"
	"time"
)

const CLEANUP_LOCK_KEY = 925955823 // Used by all instances
const BATCH_PURGE_SIZE = 100

func (d *Database) AcquireCleanupLock(ctx context.Context) (bool, error) {
	var success bool
	err := d.Pool.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, CLEANUP_LOCK_KEY).Scan(&success)
	return success, err
}

func (d *Database) ReleaseCleanupLock(ctx context.Context) {
	_, _ = d.Pool.Exec(ctx, `SELECT pg_advisory_unlock($1)`, CLEANUP_LOCK_KEY)
}

func (d *Database) DeleteExpungedMessagesByContentHash(ctx context.Context, contentHash string) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction for content hash %s cleanup: %w", contentHash, err)
	}
	defer tx.Rollback(ctx)

	// Delete from message_contents
	tag, err := tx.Exec(ctx, `DELETE FROM message_contents WHERE content_hash = $1`, contentHash)
	if err != nil {
		return fmt.Errorf("failed to delete from message_contents for hash %s: %w", contentHash, err)
	}
	if tag.RowsAffected() == 0 {
		// This is not necessarily an error. The entry might have been deleted in a previous run,
		// or if the message was extremely short-lived, the content might not have been inserted.
		log.Printf("[DB] no rows deleted from message_contents for hash %s (may have been already deleted or never created)", contentHash)
	}

	// Delete from messages (only expunged entries)
	_, err = tx.Exec(ctx, `
		DELETE 
			FROM messages
		WHERE 
			content_hash = $1 AND 
			expunged_at IS NOT NULL
	`, contentHash)
	if err != nil {
		return fmt.Errorf("failed to delete expunged messages for hash %s: %w", contentHash, err)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to cleanup content hash %s: %w", contentHash, err)
	}

	return nil
}

// ExpungeOldMessages marks messages older than the specified duration as expunged
// This enables automatic cleanup of old messages based on age restriction
func (d *Database) ExpungeOldMessages(ctx context.Context, olderThan time.Duration) (int64, error) {
	threshold := time.Now().Add(-olderThan).UTC()

	result, err := d.Pool.Exec(ctx, `
		UPDATE messages
		SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
		WHERE created_at < $1 AND expunged_at IS NULL
	`, threshold)

	if err != nil {
		return 0, fmt.Errorf("failed to expunge old messages: %w", err)
	}

	return result.RowsAffected(), nil
}

// GetContentHashesForFullCleanup identifies content_hash values for which all associated messages
// are expunged and older than the specified 'olderThan' duration (grace period).
// These content_hash values are candidates for complete removal from S3, message_contents, and messages table.
func (d *Database) GetContentHashesForFullCleanup(ctx context.Context, olderThan time.Duration, limit int) ([]string, error) {
	threshold := time.Now().Add(-olderThan).UTC()
	rows, err := d.Pool.Query(ctx, `
		WITH deletable_hashes AS (
			SELECT content_hash
			FROM messages m
			GROUP BY content_hash
			HAVING bool_and(expunged_at IS NOT NULL AND expunged_at < $1)
		)
		SELECT content_hash FROM deletable_hashes
		LIMIT $2;
	`, threshold, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query for content hashes for full cleanup: %w", err)
	}
	defer rows.Close()

	var result []string
	for rows.Next() {
		var contentHash string
		if err := rows.Scan(&contentHash); err != nil {
			continue
		}
		result = append(result, contentHash)
	}
	return result, nil
}
