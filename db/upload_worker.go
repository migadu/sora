package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
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

// PendingUploadWithEmail extends PendingUpload with account email for display
type PendingUploadWithEmail struct {
	PendingUpload
	AccountEmail string
}

// AcquireAndLeasePendingUploads selects pending uploads for a given instance,
// locks them to prevent concurrent processing by other workers, and updates their
// last_attempt timestamp to "lease" them to the current worker.
// This is the recommended method for workers to fetch tasks.
func (db *Database) AcquireAndLeasePendingUploads(ctx context.Context, tx pgx.Tx, instanceId string, limit int, retryInterval time.Duration, maxAttempts int) ([]PendingUpload, error) {
	retryTasksLastAttemptBefore := time.Now().Add(-retryInterval)

	rows, err := tx.Query(ctx, `
		SELECT id, account_id, content_hash, size, instance_id, attempts, created_at, updated_at, last_attempt
		FROM pending_uploads
		WHERE instance_id = $1
		  AND (attempts < $2)
		  AND ((last_attempt IS NULL) OR (last_attempt < $3))
		ORDER BY created_at ASC, id ASC
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

	return uploads, nil
}

// MarkUploadAttempt increments the attempt count for a pending upload.
// This is called when an upload attempt fails.
func (db *Database) MarkUploadAttempt(ctx context.Context, tx pgx.Tx, contentHash string, accountID int64) error {
	_, err := tx.Exec(ctx, `
		UPDATE pending_uploads
		SET attempts = attempts + 1, last_attempt = now()
		WHERE content_hash = $1 AND account_id = $2`, contentHash, accountID)
	return err
}

// CompleteS3Upload marks all messages with the given content hash as uploaded
// and deletes the specific pending upload record.
// Called by an upload worker after successfully uploading the content hash.
func (db *Database) CompleteS3Upload(ctx context.Context, tx pgx.Tx, contentHash string, accountID int64) error {
	// Only mark messages for the specific account as uploaded.
	_, err := tx.Exec(ctx, `
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

	return nil
}

// IsContentHashUploaded checks if any non-expunged message with the given content hash
// is already marked as uploaded.  This is used by the upload worker to avoid redundant
// S3 uploads.
//
// IMPORTANT: Only considers non-expunged messages.  Expunged messages may be pending
// S3 cleanup by the cleaner.  If we consider them "uploaded", the worker skips the
// upload, then the cleaner deletes the S3 object, leaving new messages that reference
// a non-existent object (404 NoSuchKey on fetch).
func (db *Database) IsContentHashUploaded(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	var uploaded bool
	err := db.GetReadPool().QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM messages WHERE content_hash = $1 AND account_id = $2 AND uploaded = TRUE AND expunged_at IS NULL)
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

// InstanceUploadStats holds upload statistics for a specific instance
type InstanceUploadStats struct {
	InstanceID string
	Count      int64
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

// GetPendingUploadsByInstance returns upload counts grouped by instance_id
func (db *Database) GetPendingUploadsByInstance(ctx context.Context) ([]InstanceUploadStats, error) {
	rows, err := db.GetReadPool().Query(ctx, `
		SELECT instance_id, COUNT(*)
		FROM pending_uploads
		GROUP BY instance_id
		ORDER BY COUNT(*) DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending uploads by instance: %w", err)
	}
	defer rows.Close()

	var result []InstanceUploadStats
	for rows.Next() {
		var stat InstanceUploadStats
		if err := rows.Scan(&stat.InstanceID, &stat.Count); err != nil {
			return nil, fmt.Errorf("failed to scan instance stats: %w", err)
		}
		result = append(result, stat)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating instance stats: %w", err)
	}

	return result, nil
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

// GetFailedUploadsWithEmail returns failed uploads with account email for display purposes
func (db *Database) GetFailedUploadsWithEmail(ctx context.Context, maxAttempts int, limit int) ([]PendingUploadWithEmail, error) {
	rows, err := db.GetReadPool().Query(ctx, `
		SELECT
			p.id, p.account_id, p.content_hash, p.size, p.instance_id,
			p.attempts, p.created_at, p.updated_at, p.last_attempt,
			c.address as account_email
		FROM pending_uploads p
		JOIN accounts a ON p.account_id = a.id
		JOIN credentials c ON a.id = c.account_id AND c.primary_identity = TRUE
		WHERE p.attempts >= $1
		ORDER BY p.created_at DESC
		LIMIT $2
	`, maxAttempts, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query failed uploads with email: %w", err)
	}
	defer rows.Close()

	var uploads []PendingUploadWithEmail
	for rows.Next() {
		var u PendingUploadWithEmail
		if err := rows.Scan(
			&u.ID, &u.AccountID, &u.ContentHash, &u.Size, &u.InstanceID,
			&u.Attempts, &u.CreatedAt, &u.UpdatedAt, &u.LastAttempt,
			&u.AccountEmail,
		); err != nil {
			return nil, fmt.Errorf("failed to scan failed upload: %w", err)
		}
		uploads = append(uploads, u)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating failed uploads: %w", err)
	}

	return uploads, nil
}

// RecordInstanceHeartbeat marks this instance as alive right now.
//
// The heartbeat is the liveness signal db.CleanupFailedUploads uses to decide whether
// an unfinished upload is still recoverable: only the instance that created a
// pending_upload can perform it (the body is on that node's local disk), so a
// still-beating owner means "do not reap", and an owner that stopped beating for
// longer than the liveness threshold means "the disk holding those bytes is gone".
func (db *Database) RecordInstanceHeartbeat(ctx context.Context, tx pgx.Tx, instanceID string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO instance_heartbeats (instance_id, last_seen)
		VALUES ($1, now())
		ON CONFLICT (instance_id) DO UPDATE SET last_seen = now()
	`, instanceID)
	if err != nil {
		return fmt.Errorf("failed to record heartbeat for instance %s: %w", instanceID, err)
	}
	return nil
}

// StrandedUploadInstance describes an instance_id that still owns retryable pending
// uploads (attempts < maxAttempts) but has shown no sign of life within the liveness
// threshold. Their uploads make no progress and are invisible to the failed-upload
// alerting, which only counts attempts >= maxAttempts.
type StrandedUploadInstance struct {
	InstanceID    string
	PendingCount  int64
	PendingBytes  int64
	OldestPending time.Time
	// LastSeen is the instance's last heartbeat; invalid means it never recorded one,
	// which makes its liveness UNKNOWN rather than dead, so none of its uploads are reaped.
	LastSeen sql.NullTime
	// LastLease is the most recent lease it took on any of its own uploads. It is
	// evidence of life even from a build that predates the heartbeat table.
	LastLease sql.NullTime
}

// GetStrandedUploadInstances returns the instances whose retryable uploads are not
// making progress because the owning instance shows no sign of life. Reported so an
// operator learns both that mail is about to be dropped (dead instance) and that a
// backlog can never be reaped (unknown liveness).
func (db *Database) GetStrandedUploadInstances(ctx context.Context, maxAttempts int, livenessThreshold time.Duration) ([]StrandedUploadInstance, error) {
	// Report only the worst offenders: instance ids are per host and churn with
	// container lifecycles, so the list is unbounded in principle.
	const maxReported = 20

	// Same rule as db.CleanupFailedUploads, against the database clock that wrote the
	// heartbeats and leases: the most recent evidence of life decides, and no evidence
	// at all means unknown rather than gone.
	rows, err := db.GetReadPool().Query(ctx, `
		SELECT pu.instance_id, COUNT(*), COALESCE(SUM(pu.size), 0), MIN(pu.created_at),
		       ih.last_seen, MAX(pu.last_attempt)
		FROM pending_uploads pu
		LEFT JOIN instance_heartbeats ih ON ih.instance_id = pu.instance_id
		WHERE pu.attempts < $1
		GROUP BY pu.instance_id, ih.last_seen
		HAVING GREATEST(ih.last_seen, MAX(pu.last_attempt)) IS NULL
		    OR GREATEST(ih.last_seen, MAX(pu.last_attempt)) < now() - $2::interval
		ORDER BY COUNT(*) DESC
		LIMIT $3
	`, maxAttempts, livenessThreshold, maxReported)
	if err != nil {
		return nil, fmt.Errorf("failed to query stranded upload instances: %w", err)
	}
	defer rows.Close()

	var result []StrandedUploadInstance
	for rows.Next() {
		var s StrandedUploadInstance
		if err := rows.Scan(&s.InstanceID, &s.PendingCount, &s.PendingBytes, &s.OldestPending, &s.LastSeen, &s.LastLease); err != nil {
			return nil, fmt.Errorf("failed to scan stranded upload instance: %w", err)
		}
		result = append(result, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating stranded upload instances: %w", err)
	}

	return result, nil
}

// ExhaustUploadAttempts sets the attempt count to maxAttempts for the given upload,
// immediately marking it as permanently failed without cycling through retries one by one.
// Use this when the content is confirmed permanently lost (file missing AND not in S3).
func (d *Database) ExhaustUploadAttempts(ctx context.Context, tx pgx.Tx, contentHash string, accountID int64, maxAttempts int) error {
	_, err := tx.Exec(ctx, `
		UPDATE pending_uploads
		SET attempts = $3, last_attempt = now()
		WHERE content_hash = $1 AND account_id = $2`,
		contentHash, accountID, maxAttempts)
	return err
}

// DeleteFailedUpload deletes the pending_uploads record and any unuploaded message rows
// for the given content hash + account. Used by the admin tool to clean up entries where
// the content is permanently lost ([FAIL] MISSING in S3 and no local file).
// Returns the number of message rows that were deleted.
func (d *Database) DeleteFailedUpload(ctx context.Context, tx pgx.Tx, contentHash string, accountID int64) (int64, error) {
	var deleted int64
	err := tx.QueryRow(ctx, `
		WITH deleted_messages AS (
			DELETE FROM messages
			WHERE content_hash = $1 AND account_id = $2 AND uploaded = FALSE
			RETURNING id
		),
		deleted_pending AS (
			DELETE FROM pending_uploads
			WHERE content_hash = $1 AND account_id = $2
		)
		SELECT count(*) FROM deleted_messages
	`, contentHash, accountID).Scan(&deleted)
	if err != nil {
		return 0, fmt.Errorf("failed to delete failed upload (hash=%s, account=%d): %w", contentHash, accountID, err)
	}
	return deleted, nil
}

// PendingUploadExists checks if a pending upload record exists for the given content hash and account.
// This is used by the cleanup job to determine if a local file is orphaned.
func (db *Database) PendingUploadExists(ctx context.Context, contentHash string, accountID int64) (bool, error) {
	var exists bool
	err := db.GetReadPool().QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM pending_uploads WHERE content_hash = $1 AND account_id = $2)
	`, contentHash, accountID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if pending upload exists for content hash %s, account %d: %w", contentHash, accountID, err)
	}
	return exists, nil
}
