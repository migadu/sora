package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// insertCleanupMessage inserts one message row for the S3 lock tests. expungedAt of the
// zero time leaves the message active.
func insertCleanupMessage(t *testing.T, database *Database, accountID, mailboxID int64, uid int, hash string, expungedAt time.Time) {
	t.Helper()
	ctx := context.Background()

	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `
		WITH inserted AS (
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq, expunged_at, expunged_modseq)
			VALUES ($1, $2, $3, $4, now(), now(), 100, TRUE, 'example.com', 'user', $5, 'body', '[]', $3, $6, CASE WHEN $6::timestamptz IS NULL THEN NULL ELSE nextval('messages_modseq') END)
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags)
		SELECT id, mailbox_id, 0 FROM inserted
	`, accountID, mailboxID, uid, hash, fmt.Sprintf("msgid%s", hash), nullableTime(expungedAt))
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
}

func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// lockHolderState returns the state of the backend holding the session-level advisory
// lock for lockID, e.g. "idle" or "idle in transaction".
func lockHolderState(t *testing.T, database *Database, lockID int64) (string, bool) {
	t.Helper()

	classID := int64(uint64(lockID) >> 32)
	objID := int64(uint32(uint64(lockID)))

	var state string
	err := database.GetWritePool().QueryRow(context.Background(), `
		SELECT a.state
		FROM pg_locks l
		JOIN pg_stat_activity a ON a.pid = l.pid
		WHERE l.locktype = 'advisory'
		  AND l.classid = $1::bigint::oid
		  AND l.objid = $2::bigint::oid
		  AND l.objsubid = 1
		  AND l.granted
	`, classID, objID).Scan(&state)
	if err != nil {
		return "", false
	}
	return state, true
}

// tryLockFromOtherSession reports whether another session can take the object lock,
// i.e. whether the cleaner is really holding it.
func tryLockFromOtherSession(t *testing.T, database *Database, lockID int64) bool {
	t.Helper()
	ctx := context.Background()

	conn, err := database.GetWritePool().Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()

	var acquired bool
	require.NoError(t, conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", lockID).Scan(&acquired))
	if acquired {
		var released bool
		require.NoError(t, conn.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", lockID).Scan(&released))
	}
	return acquired
}

// TestExecuteWithLockedS3Orphans covers the safety contract of the cleaner's S3
// deletion path against a live database:
//
//   - only genuine orphans reach the callback (an active message, a message expunged
//     inside the grace period, or a pending upload all disqualify a body),
//   - the per-object advisory lock — the one the uploader takes around its PUT — is
//     held for the whole callback and released afterwards,
//   - the locking session has NO transaction open while the callback runs, so the S3
//     round trip inside it cannot pin a write transaction,
//   - a body whose lock is already held (an upload in flight) is skipped rather than
//     deleted.
func TestExecuteWithLockedS3Orphans(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer database.Close()

	ctx := context.Background()
	const gracePeriod = time.Hour
	suffix := time.Now().UnixNano()

	orphanHash := fmt.Sprintf("s3lock_orphan_%d", suffix)
	activeHash := fmt.Sprintf("s3lock_active_%d", suffix)
	recentHash := fmt.Sprintf("s3lock_recent_%d", suffix)
	pendingHash := fmt.Sprintf("s3lock_pending_%d", suffix)
	uploadingHash := fmt.Sprintf("s3lock_uploading_%d", suffix)

	longAgo := time.Now().Add(-24 * time.Hour)
	insertCleanupMessage(t, database, accountID, mailboxID, 200, orphanHash, longAgo)
	insertCleanupMessage(t, database, accountID, mailboxID, 201, activeHash, time.Time{})
	insertCleanupMessage(t, database, accountID, mailboxID, 202, recentHash, time.Now().Add(-time.Minute))
	insertCleanupMessage(t, database, accountID, mailboxID, 203, pendingHash, longAgo)
	insertCleanupMessage(t, database, accountID, mailboxID, 204, uploadingHash, longAgo)

	_, err := database.GetWritePool().Exec(ctx, `
		INSERT INTO pending_uploads (account_id, instance_id, content_hash, size)
		VALUES ($1, 'test-instance', $2, 100)
	`, accountID, pendingHash)
	require.NoError(t, err)

	candidates := make([]UserScopedObjectForCleanup, 0, 5)
	for _, hash := range []string{orphanHash, activeHash, recentHash, pendingHash, uploadingHash} {
		candidates = append(candidates, UserScopedObjectForCleanup{
			AccountID: accountID, ContentHash: hash, S3Domain: "example.com", S3Localpart: "user",
		})
	}

	// An uploader is mid-PUT for uploadingHash: it holds the object lock on its own session.
	uploaderConn, err := database.GetWritePool().Acquire(ctx)
	require.NoError(t, err)
	uploadingLockID := GetS3ObjectLockID(accountID, uploadingHash)
	_, err = uploaderConn.Exec(ctx, "SELECT pg_advisory_lock($1)", uploadingLockID)
	require.NoError(t, err)

	orphanLockID := GetS3ObjectLockID(accountID, orphanHash)

	var seen []string
	var holderState string
	var holderFound, lockedDuringCallback bool
	err = database.ExecuteWithLockedS3Orphans(ctx, candidates, gracePeriod, func(orphans []UserScopedObjectForCleanup) error {
		for _, o := range orphans {
			seen = append(seen, o.ContentHash)
		}
		lockedDuringCallback = !tryLockFromOtherSession(t, database, orphanLockID)
		holderState, holderFound = lockHolderState(t, database, orphanLockID)
		return nil
	})
	require.NoError(t, err)
	require.True(t, holderFound, "the backend holding the object lock must be visible in pg_locks")

	_, err = uploaderConn.Exec(ctx, "SELECT pg_advisory_unlock($1)", uploadingLockID)
	require.NoError(t, err)
	uploaderConn.Release()

	assert.Equal(t, []string{orphanHash}, seen,
		"only the body with no live, recently expunged or pending reference may be deleted")
	assert.True(t, lockedDuringCallback,
		"the object lock must be held for the whole callback, so an upload cannot race the delete")
	assert.NotEqual(t, "idle in transaction", holderState,
		"the S3 delete must not run inside an open write transaction")
	assert.True(t, tryLockFromOtherSession(t, database, orphanLockID),
		"the object lock must be released once the callback returns")
}
