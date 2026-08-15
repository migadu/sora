package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestQResyncHonoursMasterDBPin proves (or disproves) that the QRESYNC read path
// in db/qresync.go drops the session's master-DB pin.
//
// server/imap/select.go:50-53 puts consts.UseMasterDBKey into readCtx when the
// session is pinned (s.useMasterDB, set by APPEND/STORE/EXPUNGE/MOVE/COPY) and
// passes that context to GetActiveUIDsInSetWithRetry, GetVanishedUIDsWithRetry
// and GetMessagesChangedSinceWithRetry, exactly so a session that just wrote
// reads its own writes back from the master instead of a lagging replica.
// db/qresync.go, however, calls db.GetReadPool() rather than
// db.GetReadPoolWithContext(ctx) for every one of its queries, so the pin has no
// effect and the client gets a stale VANISHED / changed-since set.
//
// Setup mirrors TestPollMailboxHonoursMasterDBPin: a *Database whose WritePool
// is the real (master) test DB and whose ReadPool is a lagging-replica pool
// snapshotted before the master moves ahead.
func TestQResyncHonoursMasterDBPin(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	master := setupTestDatabase(t)
	defer master.Close()
	ctx := context.Background()

	// ---- master state: account + mailbox + 3 messages ------------------
	testEmail := fmt.Sprintf("test_qresyncpin_%d@example.com", time.Now().UnixNano())
	tx, err := master.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = master.CreateAccount(ctx, tx, CreateAccountRequest{
		Email: testEmail, Password: "password", IsPrimary: true, HashType: "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err := master.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	tx, err = master.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, master.CreateMailbox(ctx, tx, accountID, "INBOX", nil))
	require.NoError(t, tx.Commit(ctx))

	mailbox, err := master.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	mailboxID := mailbox.ID

	tx, err = master.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	for _, uid := range []uint32{201, 202, 203} {
		insertTestMessageWithUIDForPoll(t, master, ctx, tx, accountID, mailboxID, "INBOX", uid, nil)
	}
	require.NoError(t, tx.Commit(ctx))

	// ---- snapshot the replica: this is the client's last-synced state ---
	schema := fmt.Sprintf("qresync_pin_replica_%d", time.Now().UnixNano())
	_, err = master.GetWritePool().Exec(ctx, fmt.Sprintf("CREATE SCHEMA %s", schema))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = master.GetWritePool().Exec(context.Background(),
			fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schema))
	})

	for _, stmt := range []string{
		fmt.Sprintf("CREATE TABLE %s.mailboxes AS SELECT * FROM public.mailboxes WHERE id = %d", schema, mailboxID),
		fmt.Sprintf("CREATE TABLE %s.mailbox_stats AS SELECT * FROM public.mailbox_stats WHERE mailbox_id = %d", schema, mailboxID),
		fmt.Sprintf("CREATE TABLE %s.messages AS SELECT * FROM public.messages WHERE mailbox_id = %d", schema, mailboxID),
		fmt.Sprintf("CREATE TABLE %s.message_state AS SELECT * FROM public.message_state WHERE mailbox_id = %d", schema, mailboxID),
	} {
		_, err = master.GetWritePool().Exec(ctx, stmt)
		require.NoError(t, err, "failed to build replica snapshot: %s", stmt)
	}

	sinceModSeq := getHighestModSeq(t, master, ctx, mailboxID)

	var snapshotUIDValidity uint32
	require.NoError(t, master.GetWritePool().QueryRow(ctx,
		"SELECT uid_validity FROM public.mailboxes WHERE id = $1", mailboxID).Scan(&snapshotUIDValidity))

	// ---- master moves ahead: expunge 202, flag 203, append 204, bump
	//      UIDVALIDITY -------------------------------------------------
	tx, err = master.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = master.ExpungeMessageUIDs(ctx, tx, mailboxID, imap.UID(202))
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	tx, err = master.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, _, err = master.AddMessageFlags(ctx, tx, 203, mailboxID, []imap.Flag{imap.FlagSeen})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	tx, err = master.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUIDForPoll(t, master, ctx, tx, accountID, mailboxID, "INBOX", 204, nil)
	require.NoError(t, tx.Commit(ctx))

	newUIDValidity := snapshotUIDValidity + 1
	_, err = master.GetWritePool().Exec(ctx,
		"UPDATE public.mailboxes SET uid_validity = $1 WHERE id = $2", newUIDValidity, mailboxID)
	require.NoError(t, err)

	masterModSeq := getHighestModSeq(t, master, ctx, mailboxID)
	require.Greater(t, masterModSeq, sinceModSeq, "sanity: master modseq must have advanced")

	// ---- a Database with a real master pool and a lagging read pool ----
	replicaPool := newLaggingReplicaPool(t, ctx, schema)
	defer replicaPool.Close()

	split := &Database{
		WritePool: master.GetWritePool(),
		ReadPool:  replicaPool,
	}

	pinnedCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)
	knownUIDs := imap.UIDSet{imap.UIDRange{Start: 201, Stop: 204}}

	// ---- control 1: the pin mechanism itself ---------------------------
	require.NotSame(t, split.GetReadPool(), split.GetReadPoolWithContext(pinnedCtx),
		"harness broken: pinned accessor must return a different pool than GetReadPool()")
	require.Same(t, split.GetWritePool(), split.GetReadPoolWithContext(pinnedCtx),
		"harness broken: pinned accessor must return the write (master) pool")

	// ---- control 2: the replica really is stale ------------------------
	var replicaActive, replicaExpunged int
	require.NoError(t, replicaPool.QueryRow(ctx,
		"SELECT COUNT(*)::int FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL",
		mailboxID).Scan(&replicaActive))
	require.Equal(t, 3, replicaActive, "harness broken: replica snapshot should hold UIDs 201-203, all active")
	require.NoError(t, replicaPool.QueryRow(ctx,
		"SELECT COUNT(*)::int FROM messages WHERE mailbox_id = $1 AND expunged_at IS NOT NULL",
		mailboxID).Scan(&replicaExpunged))
	require.Equal(t, 0, replicaExpunged, "harness broken: replica snapshot should hold no expunged messages")

	// ---- control 3: a context-aware read path DOES honour the pin ------
	// getUIDBySeqNum (db/message.go) uses GetReadPoolWithContext, so with the
	// same wiring and the same pinned context it sees the master's messages:
	// the master's active set is 201, 203, 204 while the replica's is 201-203.
	uid, err := split.getUIDBySeqNum(pinnedCtx, mailboxID, 3)
	require.NoError(t, err,
		"harness broken: a GetReadPoolWithContext-based read should have found the master's messages")
	require.EqualValues(t, 204, uid,
		"harness broken: pinned read should return the master's third active UID")

	// ---- control 4: unpinned QRESYNC reads see the stale replica -------
	unpinnedVanished, err := split.GetVanishedUIDs(ctx, mailboxID, sinceModSeq, masterModSeq)
	require.NoError(t, err)
	require.Empty(t, unpinnedVanished, "harness broken: an unpinned read must see the lagging replica")

	// ---- THE ASSERTIONS ------------------------------------------------
	vanished, err := split.GetVanishedUIDs(pinnedCtx, mailboxID, sinceModSeq, masterModSeq)
	require.NoError(t, err)
	assert.Equal(t, []imap.UID{202}, vanished,
		"GetVanishedUIDs ignored the master-DB pin: it read the lagging replica, so the UID expunged "+
			"on the master is missing from VANISHED (db/qresync.go uses GetReadPool(), not GetReadPoolWithContext(ctx))")

	vanishedForFetch, err := split.GetVanishedUIDsForFetch(pinnedCtx, mailboxID, sinceModSeq)
	require.NoError(t, err)
	assert.Equal(t, []imap.UID{202}, vanishedForFetch,
		"GetVanishedUIDsForFetch ignored the master-DB pin: FETCH VANISHED read the lagging replica")

	changed, err := split.GetMessagesChangedSince(pinnedCtx, mailboxID, sinceModSeq)
	require.NoError(t, err)
	changedUIDs := make([]imap.UID, 0, len(changed))
	for _, msg := range changed {
		changedUIDs = append(changedUIDs, msg.UID)
	}
	assert.Equal(t, []imap.UID{203, 204}, changedUIDs,
		"GetMessagesChangedSince ignored the master-DB pin: the flag change and the append made on the "+
			"master produced no unsolicited FETCH responses")

	activeUIDs, err := split.GetActiveUIDsInSet(pinnedCtx, mailboxID, knownUIDs)
	require.NoError(t, err)
	assert.Equal(t, []imap.UID{201, 203, 204}, activeUIDs,
		"GetActiveUIDsInSet ignored the master-DB pin: it reported the replica's active set, which still "+
			"contains the expunged UID 202 and lacks the appended UID 204")

	valid, err := split.ValidateQResyncUIDValidity(pinnedCtx, mailboxID, newUIDValidity)
	require.NoError(t, err)
	assert.True(t, valid,
		"ValidateQResyncUIDValidity ignored the master-DB pin: it compared against the replica's stale "+
			"uid_validity and would force a spurious full resync")
}
