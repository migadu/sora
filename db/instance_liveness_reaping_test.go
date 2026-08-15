package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCleanupFailedUploadsInstanceLiveness pins down BOTH directions of the reaping
// rule, because this predicate has already flip-flopped once:
//
//	round 1: reap on age alone            -> destroyed recoverable mail during an S3 outage
//	round 2: never reap while attempts<max -> uploads owned by a decommissioned instance
//	                                          are immortal, and the tables grow forever
//
// What actually separates the two is whether the node holding the bytes still exists.
// pending_uploads are leased only by their creating instance (the spool file is on that
// node's local disk), so:
//
//	owner alive,   attempts < max  -> keep   (the bytes are recoverable)
//	owner alive,   attempts >= max -> reap   (the upload is provably dead)
//	owner gone                     -> reap   (the bytes died with its disk)
//	owner liveness UNKNOWN         -> keep   (never guess; over-reaping loses mail)
func TestCleanupFailedUploadsInstanceLiveness(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, testEmail, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	ts := time.Now().UnixNano()

	const maxAttempts = 5
	const gracePeriod = 24 * time.Hour
	const liveness = time.Hour

	oldCreatedAt := time.Now().Add(-25 * time.Hour) // past the grace period
	aliveSeen := time.Now().Add(-time.Minute)       // within the liveness threshold
	deadSeen := time.Now().Add(-2 * time.Hour)      // silent for longer than it

	// Each case gets its own instance_id so the heartbeat rows cannot interfere.
	instance := func(name string) string { return fmt.Sprintf("inst_%s_%d", name, ts) }

	type upload struct {
		name        string
		attempts    int
		instanceID  string
		heartbeat   *time.Time // nil: the instance never recorded one
		lastAttempt *time.Time // nil: never leased
		wantKept    bool
		why         string
	}

	cases := []upload{
		{
			name: "alive_retrying", attempts: 0, instanceID: instance("alive"),
			heartbeat: &aliveSeen, wantKept: true,
			why: "owner is alive and has attempts left: the body is on its disk and will upload once S3 returns (round-1 P0)",
		},
		{
			name: "dead_retrying", attempts: 0, instanceID: instance("dead"),
			heartbeat: &deadSeen, wantKept: false,
			why: "owner has been silent past the liveness threshold: nothing will ever upload those bytes (round-2 hole)",
		},
		{
			name: "alive_exhausted", attempts: maxAttempts, instanceID: instance("alive"),
			heartbeat: &aliveSeen, wantKept: false,
			why: "owner is alive but gave up on this upload: it is provably dead",
		},
		{
			name: "unknown_never_seen", attempts: 0, instanceID: instance("unknown"),
			heartbeat: nil, lastAttempt: nil, wantKept: true,
			why: "no heartbeat and no lease: liveness is unknown, and uncertainty must never reap",
		},
		{
			name: "unknown_but_leasing", attempts: 0, instanceID: instance("legacy"),
			heartbeat: nil, lastAttempt: &aliveSeen, wantKept: true,
			why: "no heartbeat row, but it leased this very upload just now, so it is demonstrably alive",
		},
		{
			name: "stale_heartbeat_recent_lease", attempts: 0, instanceID: instance("mixed"),
			heartbeat: &deadSeen, lastAttempt: &aliveSeen, wantKept: true,
			why: "the most recent evidence of life wins: a stale heartbeat plus a fresh lease still means alive",
		},
	}

	hashes := make(map[string]string, len(cases))
	seenInstances := make(map[string]bool)

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	for i, c := range cases {
		hash := fmt.Sprintf("liveness_%s_%d", c.name, ts)
		hashes[c.name] = hash

		_, err := tx.Exec(ctx, `
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
		`, accountID, mailboxID, 3000+i, hash, time.Now(), fmt.Sprintf("msgid_%s", hash), oldCreatedAt)
		require.NoError(t, err)

		_, err = tx.Exec(ctx, `
			INSERT INTO pending_uploads (account_id, content_hash, size, instance_id, attempts, created_at, last_attempt)
			VALUES ($1, $2, 100, $3, $4, $5, $6)
		`, accountID, hash, c.instanceID, c.attempts, oldCreatedAt, c.lastAttempt)
		require.NoError(t, err)

		if c.heartbeat != nil && !seenInstances[c.instanceID] {
			_, err = tx.Exec(ctx, `
				INSERT INTO instance_heartbeats (instance_id, last_seen) VALUES ($1, $2)
			`, c.instanceID, *c.heartbeat)
			require.NoError(t, err)
			seenInstances[c.instanceID] = true
		}
	}
	require.NoError(t, tx.Commit(ctx))

	cleanupTx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer cleanupTx.Rollback(ctx)
	cleaned, err := db.CleanupFailedUploads(ctx, cleanupTx, gracePeriod, maxAttempts, liveness)
	require.NoError(t, err)
	require.NoError(t, cleanupTx.Commit(ctx))
	t.Logf("CleanupFailedUploads reported %d message(s) deleted", cleaned)

	count := func(query, hash string) int {
		t.Helper()
		var n int
		require.NoError(t, db.GetReadPool().QueryRow(ctx, query, hash).Scan(&n))
		return n
	}
	msgQ := `SELECT COUNT(*) FROM messages WHERE content_hash = $1`
	pendQ := `SELECT COUNT(*) FROM pending_uploads WHERE content_hash = $1`

	for _, c := range cases {
		hash := hashes[c.name]
		want := 0
		if c.wantKept {
			want = 1
		}
		assert.Equal(t, want, count(msgQ, hash), "message %q: %s", c.name, c.why)
		assert.Equal(t, want, count(pendQ, hash), "pending_upload %q: %s", c.name, c.why)
	}

	t.Logf("test account: %s", testEmail)
}

// TestCleanupFailedUploadsRejectsNonPositiveLiveness guards the degenerate
// configuration: with a threshold of zero every instance looks silent, which
// silently restores round-1 behaviour (reaping on age alone).
func TestCleanupFailedUploadsRejectsNonPositiveLiveness(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	_, err = db.CleanupFailedUploads(ctx, tx, 24*time.Hour, 5, 0)
	require.Error(t, err, "cleanup must refuse to run without a positive liveness threshold")
	assert.Contains(t, err.Error(), "liveness")
}
