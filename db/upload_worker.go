package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type PendingUpload struct {
	ID          int64
	AccountID   int64
	ContentHash string // serves also as unique identifier in S3
	InstanceID  string // hostname of the instance that created the upload
	Size        int64
	Attempts    int
	CreatedAt   time.Time
	UpdatedAt   time.Time
	LastAttempt sql.NullTime
}

// AcquireAndLeasePendingUploads selects pending uploads for a given instance,
// locks them to prevent concurrent processing by other workers, and updates their
// last_attempt timestamp to "lease" them to the current worker.
// This is the recommended method for workers to fetch tasks.
func (db *Database) AcquireAndLeasePendingUploads(ctx context.Context, instanceId string, limit int, retryInterval time.Duration, maxAttempts int) ([]PendingUpload, error) {
	tx, err := db.GetWritePool().Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	retryTasksLastAttemptBefore := time.Now().Add(-retryInterval)

	rows, err := tx.Query(ctx, `
		SELECT id, account_id, content_hash, size, instance_id, attempts, created_at, updated_at, last_attempt
		FROM pending_uploads
		WHERE instance_id = $1
		  AND (attempts < $2)
		  AND ((last_attempt IS NULL) OR (last_attempt < $3))
		ORDER BY created_at
		LIMIT $4
		FOR UPDATE SKIP LOCKED
	`, instanceId, maxAttempts, retryTasksLastAttemptBefore, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query pending uploads for acquisition: %w", err)
	}
	defer rows.Close()

	var uploads []PendingUpload
	var acquiredIDs []int64
	for rows.Next() {
		var u PendingUpload
		if err := rows.Scan(&u.ID, &u.AccountID, &u.ContentHash, &u.Size, &u.InstanceID, &u.Attempts, &u.CreatedAt, &u.UpdatedAt, &u.LastAttempt); err != nil {
			return nil, fmt.Errorf("failed to scan pending upload: %w", err)
		}
		uploads = append(uploads, u)
		acquiredIDs = append(acquiredIDs, u.ID)
	}
	if err = rows.Err(); err != nil { // Check for errors after iterating rows
		return nil, fmt.Errorf("error iterating pending uploads: %w", err)
	}

	if len(uploads) == 0 {
		// No uploads to process. Commit the (empty) transaction.
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("failed to commit transaction when no uploads found: %w", err)
		}
		return nil, nil // No error, no uploads
	}

	// Mark the acquired tasks by updating their last_attempt time to now.
	// This effectively "leases" them. If the worker processes them successfully, they'll be deleted.
	// If the worker fails and calls MarkUploadAttempt, attempts and last_attempt will be updated again.
	// If the worker crashes, these tasks will become eligible for pickup again after PENDING_UPLOAD_RETRY_INTERVAL.
	// pgx can handle []int64 directly for `= ANY($...)`.
	tag, err := tx.Exec(ctx, `
		UPDATE pending_uploads
		SET last_attempt = now()
		WHERE id = ANY($1)
	`, acquiredIDs)
	if err != nil {
		return nil, fmt.Errorf("failed to mark uploads as acquired by updating last_attempt: %w", err)
	}
	if tag.RowsAffected() != int64(len(acquiredIDs)) {
		// This would be unexpected if FOR UPDATE SKIP LOCKED worked as intended and rows weren't deleted/updated concurrently.
		return nil, fmt.Errorf("mismatch in rows updated for lease: expected %d, got %d", len(acquiredIDs), tag.RowsAffected())
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction after acquiring uploads: %w", err)
	}

	return uploads, nil
}

// MarkUploadAttempt increments the attempt count for a pending upload.
// This is called when an upload attempt fails.
func (db *Database) MarkUploadAttempt(ctx context.Context, contentHash string, accountID int64) error {
	_, err := db.GetWritePool().Exec(ctx, `
		UPDATE pending_uploads
		SET attempts = attempts + 1, last_attempt = now()
		WHERE content_hash = $1 AND account_id = $2`, contentHash, accountID)
	return err
}

// CompleteS3Upload marks all messages with the given content hash as uploaded
// and deletes the specific pending upload record.
// Called by an upload worker after successfully uploading the content hash.
func (db *Database) CompleteS3Upload(ctx context.Context, contentHash string, accountID int64) error {
	tx, err := db.GetWritePool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Only mark messages for the specific account as uploaded.
	_, err = tx.Exec(ctx, `
		UPDATE messages 
		SET uploaded = TRUE
		WHERE content_hash = $1 AND account_id = $2 AND uploaded = FALSE
	`, contentHash, accountID)
	if err != nil {
		return err
	}

	// Delete the specific pending upload for this account.
	_, err = tx.Exec(ctx, `
		DELETE FROM pending_uploads 
		WHERE content_hash = $1 AND account_id = $2
	`, contentHash, accountID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// IsContentHashUploaded checks if any message with the given content hash is already marked as uploaded.
// This is used by workers to avoid redundant S3 uploads.
func (db *Database) IsContentHashUploaded(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	var uploaded bool
	err := db.GetReadPool().QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM messages WHERE content_hash = $1 AND account_id = $2 AND uploaded = TRUE)
	`, contentHash, accountID).Scan(&uploaded)
	if err != nil {
		return false, fmt.Errorf("failed to check if content hash %s for account %d is uploaded: %w", contentHash, accountID, err)
	}
	return uploaded, nil
}

// UploaderStats holds statistics about the upload queue
type UploaderStats struct {
	TotalPending     int64
	TotalPendingSize int64
	FailedUploads    int64
	OldestPending    sql.NullTime
}

// GetUploaderStats returns statistics about pending and failed uploads
func (db *Database) GetUploaderStats(ctx context.Context, maxAttempts int) (*UploaderStats, error) {
	var stats UploaderStats

	// Get total pending uploads and their total size
	err := db.GetReadPool().QueryRow(ctx, `
		SELECT 
			COUNT(*), 
			COALESCE(SUM(size), 0),
			MIN(created_at)
		FROM pending_uploads
		WHERE attempts < $1
	`, maxAttempts).Scan(&stats.TotalPending, &stats.TotalPendingSize, &stats.OldestPending)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending upload stats: %w", err)
	}

	// Get count of failed uploads (reached max attempts)
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT COUNT(*) 
		FROM pending_uploads 
		WHERE attempts >= $1
	`, maxAttempts).Scan(&stats.FailedUploads)
	if err != nil {
		return nil, fmt.Errorf("failed to get failed upload count: %w", err)
	}

	return &stats, nil
}

// GetFailedUploads returns detailed information about failed uploads
func (db *Database) GetFailedUploads(ctx context.Context, maxAttempts int, limit int) ([]PendingUpload, error) {
	rows, err := db.GetReadPool().Query(ctx, `
		SELECT id, account_id, content_hash, size, instance_id, attempts, created_at, updated_at, last_attempt
		FROM pending_uploads
		WHERE attempts >= $1
		ORDER BY created_at DESC
		LIMIT $2
	`, maxAttempts, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query failed uploads: %w", err)
	}
	defer rows.Close()

	var uploads []PendingUpload
	for rows.Next() {
		var u PendingUpload
		if err := rows.Scan(&u.ID, &u.AccountID, &u.ContentHash, &u.Size, &u.InstanceID, &u.Attempts, &u.CreatedAt, &u.UpdatedAt, &u.LastAttempt); err != nil {
			return nil, fmt.Errorf("failed to scan failed upload: %w", err)
		}
		uploads = append(uploads, u)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating failed uploads: %w", err)
	}

	return uploads, nil
}
