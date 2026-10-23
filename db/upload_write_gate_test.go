package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The uploader writes a body without holding its S3 object lock across the transfer. It
// passes a gate first (PassS3WriteGate), which leases its pending_uploads row to it, and
// from then on relies on every deleter's orphan re-check refusing a body that still has a
// pending row, and on nothing deleting a leased row; the finalize checks that row is still
// the one it leased (CompleteLeasedS3Upload). These tests pin each part against a live
// database.

const gateTestLease = time.Minute

// leaseUntil reads a pending row's lease; ok is false when the row is gone.
func leaseUntil(t *testing.T, database *Database, pendingID int64) (lease *time.Time, ok bool) {
	t.Helper()
	err := database.GetWritePool().QueryRow(context.Background(),
		`SELECT lease_until FROM pending_uploads WHERE id = $1`, pendingID).Scan(&lease)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false
	}
	require.NoError(t, err)
	return lease, true
}

// insertKeyedMessage inserts one INBOX message row stored under example.com/<localpart>.
// expungedAt of the zero time leaves the message live.
func insertKeyedMessage(t *testing.T, database *Database, accountID, mailboxID int64, uid int, hash, localpart string, uploaded bool, expungedAt time.Time) {
	t.Helper()
	_, err := database.GetWritePool().Exec(context.Background(), `
		WITH inserted AS (
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq, expunged_at, expunged_modseq)
			VALUES ($1, $2, $3, $4, now(), now(), 100, $5, 'example.com', $6, $7, 'body', '[]', $3, $8, CASE WHEN $8::timestamptz IS NULL THEN NULL ELSE nextval('messages_modseq') END)
			RETURNING id, mailbox_id
		)
		INSERT INTO message_state (message_id, mailbox_id, flags)
		SELECT id, mailbox_id, 0 FROM inserted
	`, accountID, mailboxID, uid, hash, uploaded, localpart, fmt.Sprintf("<%s-%d@example.com>", hash, uid), nullableTime(expungedAt))
	require.NoError(t, err)
}

func TestPassS3WriteGate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	database, _, accountID, _ := setupCleanerTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	hash := fmt.Sprintf("gate_%d", time.Now().UnixNano())
	pendingID := createPendingUpload(t, database, accountID, "gate-instance", hash, 0, time.Time{}, 100)
	lockID := GetS3ObjectLockID(accountID, hash)

	gate, err := database.PassS3WriteGate(ctx, pendingID, accountID, hash, gateTestLease)
	require.NoError(t, err)
	assert.Equal(t, S3WriteOpen, gate, "nothing holds the body and its row stands")
	_, held := findLockHolder(t, database, lockID)
	assert.False(t, held, "the gate must not keep the lock: holding it across the transfer is what pinned a pooled connection per upload")
	lease, _ := leaseUntil(t, database, pendingID)
	require.NotNil(t, lease, "an open gate leases the row to the upload")
	assert.WithinDuration(t, time.Now().Add(gateTestLease), *lease, 10*time.Second)
	require.NoError(t, database.ReleasePendingUploadLease(ctx, pendingID))

	// A deleter (or a restore, or a cross-account COPY) holds the object lock.
	holder, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = holder.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockID)
	require.NoError(t, err)
	started := time.Now()
	gate, err = database.PassS3WriteGate(ctx, pendingID, accountID, hash, gateTestLease)
	require.NoError(t, err)
	assert.Equal(t, S3WriteBusy, gate, "a write must not start while a delete of the same body may be under way")
	assert.Less(t, time.Since(started), 2*time.Second, "the gate never waits for a holder")
	lease, _ = leaseUntil(t, database, pendingID)
	assert.Nil(t, lease, "a closed gate grants no lease: nothing is in flight")
	require.NoError(t, holder.Rollback(ctx))

	gate, err = database.PassS3WriteGate(ctx, pendingID, accountID, hash, gateTestLease)
	require.NoError(t, err)
	assert.Equal(t, S3WriteOpen, gate, "the gate opens once the holder is done")

	// The leased row goes (a purge), and a later delivery of the same body stages a new
	// one. The lease is still over: only the row it leased kept deleters away.
	_, err = database.GetWritePool().Exec(ctx, `DELETE FROM pending_uploads WHERE id = $1`, pendingID)
	require.NoError(t, err)
	createPendingUpload(t, database, accountID, "gate-instance", hash, 0, time.Time{}, 100)
	gate, err = database.PassS3WriteGate(ctx, pendingID, accountID, hash, gateTestLease)
	require.NoError(t, err)
	assert.Equal(t, S3WriteAbandoned, gate)
}

func TestPendingUploadLeaseRenewAndRelease(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	database, _, accountID, _ := setupCleanerTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	hash := fmt.Sprintf("lease_%d", time.Now().UnixNano())
	pendingID := createPendingUpload(t, database, accountID, "gate-instance", hash, 0, time.Time{}, 100)

	held, err := database.RenewPendingUploadLease(ctx, pendingID, gateTestLease)
	require.NoError(t, err)
	assert.True(t, held)
	lease, _ := leaseUntil(t, database, pendingID)
	require.NotNil(t, lease)
	assert.WithinDuration(t, time.Now().Add(gateTestLease), *lease, 10*time.Second)

	require.NoError(t, database.ReleasePendingUploadLease(ctx, pendingID))
	lease, ok := leaseUntil(t, database, pendingID)
	require.True(t, ok, "a released row stays, to be leased again")
	assert.Nil(t, lease)

	_, err = database.GetWritePool().Exec(ctx, `DELETE FROM pending_uploads WHERE id = $1`, pendingID)
	require.NoError(t, err)
	held, err = database.RenewPendingUploadLease(ctx, pendingID, gateTestLease)
	require.NoError(t, err)
	assert.False(t, held, "a renewal reports a row that is gone")
}

// Nothing but its own finalize may delete the pending row of an upload in flight: the
// worker does not lease it again, and account deletion leaves it, while both still take
// a row whose lease ran out or was released.
func TestLeasedPendingRowIsLeftAlone(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	database, email, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer database.Close()
	ctx := context.Background()
	suffix := time.Now().UnixNano()
	instance := fmt.Sprintf("lease-instance-%d", suffix)

	inFlight := fmt.Sprintf("lease_flight_%d", suffix)
	lapsed := fmt.Sprintf("lease_lapsed_%d", suffix)
	queued := fmt.Sprintf("lease_queued_%d", suffix)
	insertKeyedMessage(t, database, accountID, mailboxID, 600, inFlight, "user", false, time.Time{})
	insertKeyedMessage(t, database, accountID, mailboxID, 601, lapsed, "user", false, time.Time{})
	insertKeyedMessage(t, database, accountID, mailboxID, 602, queued, "user", false, time.Time{})
	inFlightID := createPendingUpload(t, database, accountID, instance, inFlight, 0, time.Time{}, 100)
	lapsedID := createPendingUpload(t, database, accountID, instance, lapsed, 0, time.Time{}, 100)
	queuedID := createPendingUpload(t, database, accountID, instance, queued, 0, time.Time{}, 100)

	gate, err := database.PassS3WriteGate(ctx, inFlightID, accountID, inFlight, gateTestLease)
	require.NoError(t, err)
	require.Equal(t, S3WriteOpen, gate)
	_, err = database.GetWritePool().Exec(ctx, `UPDATE pending_uploads SET lease_until = now() - interval '1 second' WHERE id = $1`, lapsedID)
	require.NoError(t, err)

	// The worker's next lease, however long the transfer has run past retry_interval.
	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	leasedRows, err := database.AcquireAndLeasePendingUploads(ctx, tx, instance, 10, 0, 5)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	var ids []int64
	for _, u := range leasedRows {
		ids = append(ids, u.ID)
	}
	assert.ElementsMatch(t, []int64{lapsedID, queuedID}, ids, "an upload in flight is never leased a second time")

	// Account deletion: soft delete, then the hard delete's dependents.
	tx, err = database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	require.NoError(t, database.DeleteAccount(ctx, tx, email))
	require.NoError(t, database.HardDeleteAccounts(ctx, tx, []int64{accountID}))
	require.NoError(t, tx.Commit(ctx))

	_, ok := leaseUntil(t, database, inFlightID)
	assert.True(t, ok, "account deletion must leave the row of an upload in flight")
	_, ok = leaseUntil(t, database, lapsedID)
	assert.False(t, ok, "a lapsed lease protects nothing")
	_, ok = leaseUntil(t, database, queuedID)
	assert.False(t, ok, "an upload not in flight is dropped with its account")
}

// The reviewed hazard: a purge releases an address while an upload of one of its bodies is
// still in flight, a new account takes the address, receives the same body under the same
// key, and a delete that belonged to the old account lands on the new one's object. With
// the lease, the old account cannot be finalized, and so cannot give up its address,
// before its upload has finalized: the leased row survives the hard delete, and the S3
// phase refuses the body while that row stands, so its rows remain.
func TestAddressStaysTakenWhileAnUploadIsInFlight(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	database, email, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	hash := fmt.Sprintf("address_reuse_%d", time.Now().UnixNano())
	local, _, _ := strings.Cut(email, "@")
	insertKeyedMessage(t, database, accountID, mailboxID, 100, hash, local, false, time.Time{})
	pendingID := createPendingUpload(t, database, accountID, "old-instance", hash, 0, time.Time{}, 100)
	gate, err := database.PassS3WriteGate(ctx, pendingID, accountID, hash, gateTestLease)
	require.NoError(t, err)
	require.Equal(t, S3WriteOpen, gate)

	// Mid-PUT, the account is purged: soft delete, hard delete, S3 phase, finalize.
	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	require.NoError(t, database.DeleteAccount(ctx, tx, email))
	require.NoError(t, database.HardDeleteAccounts(ctx, tx, []int64{accountID}))
	require.NoError(t, tx.Commit(ctx))
	candidates := []UserScopedObjectForCleanup{{AccountID: accountID, ContentHash: hash, S3Domain: "example.com", S3Localpart: local}}
	const purgeGrace = -24 * time.Hour // a purge keeps no expunged body
	err = database.ExecuteWithLockedS3Orphans(ctx, candidates, purgeGrace, func(_ context.Context, orphans []UserScopedObjectForCleanup) error {
		assert.Empty(t, orphans, "the S3 phase must refuse a body whose upload is in flight")
		return nil
	})
	require.NoError(t, err)
	finalize := func() int64 {
		t.Helper()
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		n, err := database.FinalizeAccountDeletions(ctx, tx, []int64{accountID})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return n
	}
	require.EqualValues(t, 0, finalize(), "the account, and with it the address, must outlive its upload in flight")

	// The upload lands and finalizes; only now can the purge take the body and the rows.
	tx, err = database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	require.NoError(t, database.CompleteLeasedS3Upload(ctx, tx, pendingID, hash, accountID, []string{"example.com/" + local + "/" + hash}))
	require.NoError(t, tx.Commit(ctx))
	err = database.ExecuteWithLockedS3Orphans(ctx, candidates, purgeGrace, func(_ context.Context, orphans []UserScopedObjectForCleanup) error {
		require.Len(t, orphans, 1, "once the upload has finalized the body is the purge's to delete")
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = database.DeleteExpungedMessagesByS3KeyPartsBatch(ctx, tx, orphans)
		require.NoError(t, err)
		return tx.Commit(ctx)
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, finalize(), "the address is released only after the body it was written under is gone")
}

// The correctness argument for not holding the lock across the transfer, end to end on
// the cleaner's real deletion path. The body's only message was expunged long ago, so
// the cleaner lists it; its pending row is all that protects the body.
func TestS3WriteGateKeepsDeletersAwayFromAnUploadInFlight(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	database, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer database.Close()
	ctx := context.Background()
	const gracePeriod = time.Hour

	hash := fmt.Sprintf("gate_flight_%d", time.Now().UnixNano())
	insertKeyedMessage(t, database, accountID, mailboxID, 300, hash, "user", true, time.Now().Add(-24*time.Hour))
	candidates := []UserScopedObjectForCleanup{{AccountID: accountID, ContentHash: hash, S3Domain: "example.com", S3Localpart: "user"}}

	// 1. A cleaner confirms the body an orphan, and a delivery of the same body stages an
	//    upload before the cleaner's delete has landed. The upload must not write now: its
	//    object would be deleted right after.
	var pendingID int64
	err := database.ExecuteWithLockedS3Orphans(ctx, candidates, gracePeriod, func(_ context.Context, orphans []UserScopedObjectForCleanup) error {
		require.Len(t, orphans, 1, "with no pending row yet the body is an orphan")
		pendingID = createPendingUpload(t, database, accountID, "gate-instance", hash, 0, time.Time{}, 100)
		gate, err := database.PassS3WriteGate(ctx, pendingID, accountID, hash, gateTestLease)
		require.NoError(t, err)
		assert.Equal(t, S3WriteBusy, gate, "an upload must not write while a delete confirmed before its row existed is under way")
		return nil
	})
	require.NoError(t, err)

	// 2. Once that delete is done the gate opens, and the upload writes holding nothing.
	gate, err := database.PassS3WriteGate(ctx, pendingID, accountID, hash, gateTestLease)
	require.NoError(t, err)
	require.Equal(t, S3WriteOpen, gate)

	// 3. Every later deleter sees the pending row and leaves the body alone, although no
	//    lock protects the upload in flight.
	err = database.ExecuteWithLockedS3Orphans(ctx, candidates, gracePeriod, func(_ context.Context, orphans []UserScopedObjectForCleanup) error {
		assert.Empty(t, orphans, "a body whose upload passed the gate must not be deleted while its pending row stands")
		return nil
	})
	require.NoError(t, err)

	// 4. The finalize takes the row with it.
	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	require.NoError(t, database.CompleteLeasedS3Upload(ctx, tx, pendingID, hash, accountID, []string{"example.com/user/" + hash}))
	require.NoError(t, tx.Commit(ctx))
	var left int
	require.NoError(t, database.GetWritePool().QueryRow(ctx, `SELECT count(*) FROM pending_uploads WHERE id = $1`, pendingID).Scan(&left))
	assert.Equal(t, 0, left)
}

func TestCompleteLeasedS3Upload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	database, _, accountID, mailboxID := setupCleanerTestDatabase(t)
	defer database.Close()
	ctx := context.Background()
	suffix := time.Now().UnixNano()

	uploaded := func(hash string) bool {
		t.Helper()
		var u bool
		require.NoError(t, database.GetWritePool().QueryRow(ctx,
			`SELECT uploaded FROM messages WHERE account_id = $1 AND content_hash = $2`, accountID, hash).Scan(&u))
		return u
	}
	pendingRows := func(hash string) int {
		t.Helper()
		var n int
		require.NoError(t, database.GetWritePool().QueryRow(ctx,
			`SELECT count(*) FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`, accountID, hash).Scan(&n))
		return n
	}

	t.Run("finalizes while the leased row stands", func(t *testing.T) {
		hash := fmt.Sprintf("leased_ok_%d", suffix)
		insertKeyedMessage(t, database, accountID, mailboxID, 400, hash, "user", false, time.Time{})
		pendingID := createPendingUpload(t, database, accountID, "gate-instance", hash, 0, time.Time{}, 100)

		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, database.CompleteLeasedS3Upload(ctx, tx, pendingID, hash, accountID, []string{"example.com/user/" + hash}))
		require.NoError(t, tx.Commit(ctx))

		assert.True(t, uploaded(hash))
		assert.Equal(t, 0, pendingRows(hash))
	})

	t.Run("ends the lease of a row that stays because a key is left to write", func(t *testing.T) {
		hash := fmt.Sprintf("leased_partial_%d", suffix)
		insertKeyedMessage(t, database, accountID, mailboxID, 402, hash, "user", false, time.Time{})
		insertKeyedMessage(t, database, accountID, mailboxID, 403, hash, "alias", false, time.Time{})
		pendingID := createPendingUpload(t, database, accountID, "gate-instance", hash, 0, time.Time{}, 100)
		_, err := database.RenewPendingUploadLease(ctx, pendingID, gateTestLease)
		require.NoError(t, err)

		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, database.CompleteLeasedS3Upload(ctx, tx, pendingID, hash, accountID, []string{"example.com/user/" + hash}))
		require.NoError(t, tx.Commit(ctx))

		lease, ok := leaseUntil(t, database, pendingID)
		require.True(t, ok, "the row stays: example.com/alias still has to be written")
		assert.Nil(t, lease, "and is free for the next lease right away")
	})

	t.Run("refuses once the leased row is gone, even when a new delivery re-created one", func(t *testing.T) {
		hash := fmt.Sprintf("leased_gone_%d", suffix)
		insertKeyedMessage(t, database, accountID, mailboxID, 401, hash, "user", false, time.Time{})
		leased := createPendingUpload(t, database, accountID, "gate-instance", hash, 0, time.Time{}, 100)
		_, err := database.GetWritePool().Exec(ctx, `DELETE FROM pending_uploads WHERE id = $1`, leased)
		require.NoError(t, err)
		createPendingUpload(t, database, accountID, "gate-instance", hash, 0, time.Time{}, 100)

		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx) // a failed require must not leave the connection held, or Close waits forever
		err = database.CompleteLeasedS3Upload(ctx, tx, leased, hash, accountID, []string{"example.com/user/" + hash})
		require.ErrorIs(t, err, ErrPendingUploadGone)
		assert.True(t, errors.Is(err, consts.ErrDBNotFound), "an answer, not a database failure: it must not trip the write breaker")
		require.NoError(t, tx.Rollback(ctx))

		// Between the gate and now the body was unprotected for a while, and a deleter
		// may have removed what was written: the rows must not claim it, and the new
		// row must stay so the next lease writes the body again.
		assert.False(t, uploaded(hash), "rows must not be marked uploaded on the strength of a lease that lapsed")
		assert.Equal(t, 1, pendingRows(hash), "the re-created row belongs to a later upload")
	})
}
