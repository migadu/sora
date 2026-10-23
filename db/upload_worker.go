package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/helpers"
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

// ResetUploadAttempts re-arms a pending upload the worker has given up on: attempts back
// to zero and the lease cleared, so the owning instance leases it again on its next tick.
// Used by sora-admin once the body turns out to be intact on that instance's disk.
// Returns whether a row was re-armed.
func (db *Database) ResetUploadAttempts(ctx context.Context, tx pgx.Tx, contentHash string, accountID int64) (bool, error) {
	tag, err := tx.Exec(ctx, `
		UPDATE pending_uploads
		SET attempts = 0, last_attempt = NULL
		WHERE content_hash = $1 AND account_id = $2`, contentHash, accountID)
	if err != nil {
		return false, fmt.Errorf("failed to reset upload attempts (hash=%s, account=%d): %w", contentHash, accountID, err)
	}
	return tag.RowsAffected() > 0, nil
}

// CompleteS3Upload finalizes an upload for (contentHash, accountID) after the objects
// under writtenKeys (full S3 keys, domain/localpart/hash) have been stored.
//
// A row is marked uploaded only when its own key now has an object: either the key is
// in writtenKeys, or a live (non-expunged) uploaded row already carries the same key —
// the object exists by the invariant every writer keeps (readers build the GET key from
// the row, so "uploaded" must never be true for a key nothing was written under). Rows
// under a key that is in neither set stay uploaded=FALSE, and the pending row is
// deleted only once no unuploaded row is left for the pair; otherwise it stays, and the
// next lease writes the keys still missing (PendingUploadKeys lists exactly those).
//
// The "same key already live" clause is what keeps the pending row from being leased
// forever: a delivery whose dedup ran before an in-flight upload finalized re-arms the
// pending row, the next lease finds no key left to write (PendingUploadKeys excludes a
// key that has a live uploaded row) and calls this with no writtenKeys — the clause
// then marks that row from the sibling that proves the object.
func (db *Database) CompleteS3Upload(ctx context.Context, tx pgx.Tx, contentHash string, accountID int64, writtenKeys []string) error {
	if err := markS3Uploaded(ctx, tx, contentHash, accountID, writtenKeys); err != nil {
		return err
	}
	return dropFinishedPendingUpload(ctx, tx, contentHash, accountID)
}

// ErrPendingUploadGone reports that the pending_uploads row an upload leased was deleted
// before the upload finalized: the account was purged, or the upload reaped. It wraps
// consts.ErrDBNotFound, so it is an answer, not a database failure.
var ErrPendingUploadGone = fmt.Errorf("pending upload is gone: %w", consts.ErrDBNotFound)

// CompleteLeasedS3Upload is CompleteS3Upload for the uploader, which writes its objects
// without holding their lock (see PassS3WriteGate). It finalizes only if the pending row
// the upload leased, identified by pendingID, still exists, and returns
// ErrPendingUploadGone otherwise; the caller must then roll back, so that the rows it
// marked are not left claiming objects nothing protected.
//
// While the row stands, no deleter can have removed the objects since the gate: every
// orphan re-check since then saw the row. Row ids come from a sequence and are never
// reused, so finding the same id proves the row stood the whole time, not merely that a
// later delivery of the same body re-created one. The row is locked after the messages
// are marked — the order CompleteS3Upload has always taken these locks in — and held to
// commit, so it cannot go between the check and the commit.
func (db *Database) CompleteLeasedS3Upload(ctx context.Context, tx pgx.Tx, pendingID int64, contentHash string, accountID int64, writtenKeys []string) error {
	if err := markS3Uploaded(ctx, tx, contentHash, accountID, writtenKeys); err != nil {
		return err
	}
	var found int
	err := tx.QueryRow(ctx, `SELECT 1 FROM pending_uploads WHERE id = $1 FOR UPDATE`, pendingID).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPendingUploadGone
	}
	if err != nil {
		return fmt.Errorf("failed to lock pending upload %d: %w", pendingID, err)
	}
	return dropFinishedPendingUpload(ctx, tx, contentHash, accountID)
}

// markS3Uploaded marks the account's rows of contentHash uploaded whose key now has an
// object; see CompleteS3Upload.
func markS3Uploaded(ctx context.Context, tx pgx.Tx, contentHash string, accountID int64, writtenKeys []string) error {
	if writtenKeys == nil {
		writtenKeys = []string{}
	}
	_, err := tx.Exec(ctx, `
		UPDATE messages m
		SET uploaded = TRUE
		WHERE m.content_hash = $1 AND m.account_id = $2 AND m.uploaded = FALSE
		  AND (
			(m.s3_domain || '/' || m.s3_localpart || '/' || m.content_hash) = ANY($3::text[])
			OR EXISTS (
				SELECT 1 FROM messages u
				WHERE u.content_hash = m.content_hash
				  AND u.account_id = m.account_id
				  AND u.s3_domain = m.s3_domain
				  AND u.s3_localpart = m.s3_localpart
				  AND u.uploaded = TRUE
				  AND u.expunged_at IS NULL
			)
		  )
	`, contentHash, accountID, writtenKeys)
	return err
}

// dropFinishedPendingUpload deletes the pair's pending row once nothing is left to write
// for it. It runs after markS3Uploaded in the same transaction, so it sees the rows just
// marked.
func dropFinishedPendingUpload(ctx context.Context, tx pgx.Tx, contentHash string, accountID int64) error {
	_, err := tx.Exec(ctx, `
		DELETE FROM pending_uploads
		WHERE content_hash = $1 AND account_id = $2
		  AND NOT EXISTS (
			SELECT 1 FROM messages
			WHERE content_hash = $1 AND account_id = $2 AND uploaded = FALSE
		  )
	`, contentHash, accountID)
	return err
}

// S3WriteGate is what PassS3WriteGate found when an upload asked to write its objects.
type S3WriteGate int

const (
	// S3WriteOpen: no deleter holds the object, and the leased pending row still stands.
	S3WriteOpen S3WriteGate = iota
	// S3WriteBusy: something holds the object's lock right now — the cleaner or a purge
	// confirming the body is an orphan and deleting it, a restore, a cross-account COPY.
	S3WriteBusy
	// S3WriteAbandoned: the leased pending row is gone (the account was purged, or the
	// upload reaped), so nothing would finalize what the upload wrote.
	S3WriteAbandoned
)

// PassS3WriteGate is what lets the uploader write a body without holding its lock across
// the transfer, which pinned one pooled connection per upload in flight.
//
// Every S3 delete (the cleaner's and the purge's) runs "lock, confirm the body is an
// orphan, delete" under the per-object lock, and the orphan re-check (filterS3Orphans)
// refuses any body that still has a pending_uploads row. A pending upload's row exists
// from the delivery that staged it until the uploader finalizes it, so a deleter whose
// re-check runs while the row exists never touches the body. The only delete that can
// still land on an upload is one whose re-check ran before the row existed, and that
// deleter holds the lock until its delete is done. Taking the lock once, after the row
// exists and before the first write, therefore orders the write after every delete that
// could remove it:
//   - a deleter holding the lock makes the gate answer S3WriteBusy, and the upload is
//     leased again after retry_interval, when that delete is over;
//   - a deleter taking the lock afterwards sees the pending row and leaves the body be.
//
// That holds only while the row stands, so the gate also reports a row already gone, and
// the finalize checks it again (CompleteLeasedS3Upload).
//
// One autocommit statement: the transaction-scoped try-lock is released when the
// statement's implicit transaction ends, so the gate costs one round trip and pins
// nothing behind any pooler. It never waits.
func (db *Database) PassS3WriteGate(ctx context.Context, pendingID, accountID int64, contentHash string) (S3WriteGate, error) {
	var acquired, pending bool
	err := db.GetWritePool().QueryRow(ctx, `
		SELECT pg_try_advisory_xact_lock($1), EXISTS (SELECT 1 FROM pending_uploads WHERE id = $2)
	`, GetS3ObjectLockID(accountID, contentHash), pendingID).Scan(&acquired, &pending)
	if err != nil {
		return S3WriteBusy, fmt.Errorf("failed to pass the write gate for hash %s of account %d: %w", contentHash, accountID, err)
	}
	switch {
	case !acquired:
		return S3WriteBusy, nil
	case !pending:
		return S3WriteAbandoned, nil
	}
	return S3WriteOpen, nil
}

// UnreferencedS3Keys returns those of keys (full S3 keys of contentHash) that no message
// row of any account references. A row references its key while something will still
// read or clean up the object for it:
//   - it is uploaded: readers fetch it, and once it is expunged the cleaner lists it
//     (GetUserScopedObjectsForCleanup lists only uploaded rows) and deletes the object;
//   - or its account still has a pending upload of the body: that upload will write the
//     key and finalize the row, and every deleter refuses a body with a pending row.
//
// A row that is neither is dead weight: nothing writes or reads its key any more, and
// CleanupFailedUploads deletes such rows without touching S3. It is exactly the state an
// abandoned upload leaves behind, since the leased finalize rolls back instead of marking
// rows uploaded, so counting it as a reference would strand the object once the cleaner
// reaps the row. The uploader asks after the pending row it leased went away while it was
// writing, holding the object's lock, before it deletes what it wrote.
//
// It reads the pool the context selects; the uploader pins it to the primary, since a
// lagging replica could miss a row that was just delivered.
func (db *Database) UnreferencedS3Keys(ctx context.Context, contentHash string, keys []string) ([]string, error) {
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT DISTINCT m.s3_domain, m.s3_localpart FROM messages m
		WHERE m.content_hash = $1
		  AND (m.uploaded OR EXISTS (
			SELECT 1 FROM pending_uploads pu
			WHERE pu.account_id = m.account_id AND pu.content_hash = m.content_hash
		  ))
	`, contentHash)
	if err != nil {
		return nil, fmt.Errorf("failed to list the keys of hash %s: %w", contentHash, err)
	}
	defer rows.Close()

	referenced := make(map[string]struct{})
	for rows.Next() {
		var domain, localpart string
		if err := rows.Scan(&domain, &localpart); err != nil {
			return nil, fmt.Errorf("failed to scan storage key parts: %w", err)
		}
		referenced[helpers.NewS3Key(domain, localpart, contentHash)] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to list the keys of hash %s: %w", contentHash, err)
	}

	var unreferenced []string
	for _, key := range keys {
		if _, ok := referenced[key]; !ok {
			unreferenced = append(unreferenced, key)
		}
	}
	return unreferenced, nil
}

// PendingUploadKeys returns the S3 keys that still have to be written before the
// account's message rows for this content hash may be marked uploaded. The keys are
// built from the s3_domain/s3_localpart recorded on each message row at insert time,
// which is what every reader uses to build its GET key. One (content_hash, account_id)
// pair can span several keys: the pair is unique in pending_uploads, while the rows
// behind it were keyed from whatever the account's primary address was when each was
// inserted. A key is left out once a non-expunged row carries it as uploaded: its object
// is already in S3, and CompleteS3Upload marks the remaining rows under it from that.
//
// Callers that need read-your-writes (the uploader: the message rows and the
// pending_uploads row commit in one transaction, and a lagging replica answering "no
// keys" would finalize an upload that never happened) pin the context to the master.
func (db *Database) PendingUploadKeys(ctx context.Context, contentHash string, accountID int64) ([]string, error) {
	rows, err := db.GetReadPoolWithContext(ctx).Query(ctx, `
		SELECT s3_domain, s3_localpart FROM messages
		WHERE content_hash = $1 AND account_id = $2
		GROUP BY s3_domain, s3_localpart
		HAVING bool_or(NOT uploaded) AND NOT bool_or(uploaded AND expunged_at IS NULL)
	`, contentHash, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve storage keys for hash %s of account %d: %w", contentHash, accountID, err)
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var domain, localpart string
		if err := rows.Scan(&domain, &localpart); err != nil {
			return nil, fmt.Errorf("failed to scan storage key parts: %w", err)
		}
		keys = append(keys, helpers.NewS3Key(domain, localpart, contentHash))
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to resolve storage keys for hash %s of account %d: %w", contentHash, accountID, err)
	}
	return keys, nil
}

// IsContentHashUploaded reports whether a non-expunged message of this account carries
// the given content hash as uploaded UNDER THE GIVEN KEY (s3_domain/s3_localpart).
// Readers use it to tell "the body is on its way, retry" from "the body is gone": the
// question is whether a retry of THIS row's key would find an object, so only a row
// with the same key is evidence. Rows under another key are not — one account's rows
// can carry different keys (the primary address at the time each was written, or the
// address an import ran under).
//
// IMPORTANT: Only considers non-expunged messages.  Expunged messages may be pending
// S3 cleanup by the cleaner.  If we consider them "uploaded", the worker skips the
// upload, then the cleaner deletes the S3 object, leaving new messages that reference
// a non-existent object (404 NoSuchKey on fetch).
func (db *Database) IsContentHashUploaded(ctx context.Context, contentHash string, accountID int64, s3Domain, s3Localpart string) (bool, error) {
	var uploaded bool
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM messages
			WHERE content_hash = $1 AND account_id = $2
			  AND s3_domain = $3 AND s3_localpart = $4
			  AND uploaded = TRUE AND expunged_at IS NULL
		)
	`, contentHash, accountID, s3Domain, s3Localpart).Scan(&uploaded)
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
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM pending_uploads WHERE content_hash = $1 AND account_id = $2)
	`, contentHash, accountID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if pending upload exists for content hash %s, account %d: %w", contentHash, accountID, err)
	}
	return exists, nil
}

// PendingUploadRetryable reports whether a pending upload for (contentHash, accountID)
// exists that the upload worker will still lease, i.e. one with attempts below
// maxAttempts. Readers use it to tell a body that is still on its way ("retry later")
// from one the worker has given up on: a row at or past maxAttempts is never leased
// again (AcquireAndLeasePendingUploads) and is eventually reaped by
// CleanupFailedUploads, so telling a client to retry it would be telling it to retry
// forever — which is what an IMAP client that batches body fetches turns into
// "cannot get mail" for the whole mailbox.
func (db *Database) PendingUploadRetryable(ctx context.Context, contentHash string, accountID int64, maxAttempts int) (bool, error) {
	var retryable bool
	err := db.GetReadPoolWithContext(ctx).QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pending_uploads
			WHERE content_hash = $1 AND account_id = $2 AND attempts < $3
		)
	`, contentHash, accountID, maxAttempts).Scan(&retryable)
	if err != nil {
		return false, fmt.Errorf("failed to check if pending upload is retryable for content hash %s, account %d: %w", contentHash, accountID, err)
	}
	return retryable, nil
}
