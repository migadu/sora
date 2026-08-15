package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestP0A_CleanupFailedUploadsIgnoresAttempts proves that CleanupFailedUploads
// deletes recoverable mail: its DELETE predicate is only
//
//	uploaded = FALSE AND created_at < threshold
//
// and never looks at pending_uploads.attempts. A message whose upload has never
// been given up on (attempts = 0 — exactly the state server/uploader/worker.go
// deliberately maintains during a prolonged *transient* S3 outage, see the
// comment at worker.go:531-543 "Transient S3 errors ... should NOT count ...
// This prevents message loss from CleanupFailedUploads running after
// max_attempts is exhausted") is destroyed the moment it is older than the
// grace period, indistinguishably from a message whose attempts are exhausted.
//
// created_at and gracePeriod are both injectable (created_at is written
// explicitly, gracePeriod is an argument), so no 14-day wait is required.
func TestP0A_CleanupFailedUploadsIgnoresAttempts(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	ts := time.Now().UnixNano()

	const maxAttempts = 5                           // uploader's configured max_attempts
	const gracePeriod = 24 * time.Hour              // cleaner grace period
	const liveness = time.Hour                      // silence after which an instance counts as gone
	oldCreatedAt := time.Now().Add(-25 * time.Hour) // older than the grace period

	// The owning instance is alive: it heartbeats right now, so the only thing that
	// could justify reaping its uploads is exhausted attempts.
	instanceID := fmt.Sprintf("p0a_instance_%d", ts)
	_, err := db.GetWritePool().Exec(ctx,
		`INSERT INTO instance_heartbeats (instance_id, last_seen) VALUES ($1, now())`, instanceID)
	require.NoError(t, err)

	// recoverableHash: upload never given up on. Transient S3 failures do not
	// increment attempts, so this row sits at attempts = 0 forever while S3 is
	// down. The message body is still on local disk; once S3 recovers the
	// uploader would deliver it.
	recoverableHash := fmt.Sprintf("p0a_recoverable_%d", ts)
	// exhaustedHash: upload permanently failed, attempts >= maxAttempts.
	// This is the row cleanup is actually meant to reap.
	exhaustedHash := fmt.Sprintf("p0a_exhausted_%d", ts)

	insert := func(hash string, uid int, attempts int) {
		t.Helper()

		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)

		_, err = tx.Exec(ctx, `
			INSERT INTO messages_fts (content_hash, text_body, text_body_tsv)
			VALUES ($1, 'body', to_tsvector('english', 'body'))
		`, hash)
		require.NoError(t, err)

		_, err = tx.Exec(ctx, `
			WITH inserted AS (
				INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date,
				                      size, uploaded, s3_domain, s3_localpart, message_id, body_structure,
				                      recipients_json, created_modseq, created_at)
				VALUES ($1, $2, $3, $4, $5, $5, 100, FALSE, 'domain', 'part', $6, 'body', '[]', $3, $7)
				RETURNING id, mailbox_id
			)
			INSERT INTO message_state (message_id, mailbox_id, flags)
			SELECT id, mailbox_id, 0 FROM inserted
		`, accountID, mailboxID, uid, hash, time.Now(), fmt.Sprintf("msgid_%s", hash), oldCreatedAt)
		require.NoError(t, err)

		_, err = tx.Exec(ctx, `
			INSERT INTO pending_uploads (account_id, content_hash, size, instance_id, attempts, created_at)
			VALUES ($1, $2, 100, $5, $3, $4)
		`, accountID, hash, attempts, oldCreatedAt, instanceID)
		require.NoError(t, err)

		require.NoError(t, tx.Commit(ctx))
	}

	insert(recoverableHash, 900, 0)         // never given up on
	insert(exhaustedHash, 901, maxAttempts) // permanently failed

	// Sanity: both rows exist, and their attempts are as configured.
	var attempts int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT attempts FROM pending_uploads WHERE content_hash = $1`, recoverableHash).Scan(&attempts))
	require.Equal(t, 0, attempts, "precondition: recoverable upload must have attempts = 0")
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		`SELECT attempts FROM pending_uploads WHERE content_hash = $1`, exhaustedHash).Scan(&attempts))
	require.Equal(t, maxAttempts, attempts, "precondition: exhausted upload must have attempts >= maxAttempts")

	// Run the cleanup with a grace period shorter than the rows' age.
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	cleaned, err := db.CleanupFailedUploads(ctx, tx, gracePeriod, maxAttempts, liveness)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	t.Logf("CleanupFailedUploads reported %d message(s) deleted", cleaned)

	count := func(query, hash string) int {
		t.Helper()
		var n int
		require.NoError(t, db.GetReadPool().QueryRow(ctx, query, hash).Scan(&n))
		return n
	}

	msgQ := `SELECT COUNT(*) FROM messages WHERE content_hash = $1`
	pendQ := `SELECT COUNT(*) FROM pending_uploads WHERE content_hash = $1`

	// CONTRAST (expected to hold): a genuinely exhausted upload is reaped.
	assert.Equal(t, 0, count(msgQ, exhaustedHash),
		"exhausted upload (attempts >= maxAttempts) should be reaped — this is the intended behaviour")
	assert.Equal(t, 0, count(pendQ, exhaustedHash),
		"exhausted pending_uploads row should be reaped")

	// RED ASSERTION: the recoverable upload (attempts = 0) must survive.
	// It fails today: the query cannot tell the two rows apart.
	assert.Equal(t, 1, count(msgQ, recoverableHash),
		"DATA LOSS: message with pending_uploads.attempts = 0 (upload never exhausted, "+
			"body still recoverable once S3 returns) was DELETED by CleanupFailedUploads. "+
			"The DELETE predicate is only 'uploaded = FALSE AND created_at < threshold' — "+
			"it never joins pending_uploads and never inspects attempts, so a message held "+
			"back solely by a transient S3 outage is destroyed exactly like a permanently "+
			"failed one.")
	assert.Equal(t, 1, count(pendQ, recoverableHash),
		"DATA LOSS: pending_uploads row with attempts = 0 was deleted too, so the upload "+
			"can never be retried after S3 recovers")

	t.Logf("test account: %s", testEmail)
}
