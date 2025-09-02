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
		SELECT account_id, content_hash
		FROM messages
		GROUP BY account_id, content_hash
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
		if err := rows.Scan(&candidate.AccountID, &candidate.ContentHash); err != nil {
			// Log and continue to process other rows
			log.Printf("failed to scan user-scoped object for cleanup: %v", err)
			continue
		}
		result = append(result, candidate)
	}
	return result, nil
}

// DeleteExpungedMessagesByUserAndContentHash deletes all expunged message rows
// from the database that match the given AccountID and ContentHash.
// It does NOT delete from message_contents, as the content may be shared.
func (d *Database) DeleteExpungedMessagesByUserAndContentHash(ctx context.Context, accountID int64, contentHash string) error {
	_, err := d.GetWritePool().Exec(ctx, `
		DELETE FROM messages
		WHERE account_id = $1 AND content_hash = $2 AND expunged_at IS NOT NULL
	`, accountID, contentHash)
	if err != nil {
		return fmt.Errorf("failed to delete expunged messages for account %d and hash %s: %w", accountID, contentHash, err)
	}
	return nil
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

// GetUnusedContentHashes finds content_hash values in message_contents that are no longer
// referenced by any active (non-expunged) message. These are candidates for global cleanup.
func (d *Database) GetUnusedContentHashes(ctx context.Context, limit int) ([]string, error) {
	rows, err := d.GetReadPool().Query(ctx, `
		SELECT mc.content_hash
		FROM message_contents mc
		WHERE NOT EXISTS (
			SELECT 1
			FROM messages m
			WHERE m.content_hash = mc.content_hash AND m.expunged_at IS NULL
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
