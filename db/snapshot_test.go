package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInReadSnapshotIsolatesConcurrentOverwritesAndExpunges(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("readsnapshot_%d@example.com", ts), "password")
	mailboxName := fmt.Sprintf("ReadSnapshot_%d", ts)
	mailboxID := createTestMailbox(t, database, accountID, mailboxName)

	write := func(f func(tx pgx.Tx) error) {
		t.Helper()
		tx, err := database.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, f(tx))
		require.NoError(t, tx.Commit(ctx))
	}
	insert := func(uid uint32, flags ...imap.Flag) {
		t.Helper()
		write(func(tx pgx.Tx) error {
			insertTestMessageWithUIDForPoll(t, database, ctx, tx, accountID, mailboxID, mailboxName, uid, flags)
			return nil
		})
	}
	addFlags := func(uid imap.UID, flags ...imap.Flag) {
		t.Helper()
		write(func(tx pgx.Tx) error {
			_, _, err := database.AddMessageFlags(ctx, tx, uid, mailboxID, flags)
			return err
		})
	}

	// Client cached state: UIDs 1-3 at modseq since; 1 and 2 are \Seen, 3 is unseen.
	insert(1, imap.FlagSeen)
	insert(2, imap.FlagSeen)
	insert(3)
	since := getHighestModSeq(t, database, ctx, mailboxID)

	// Changes before SELECT's summary: UID 4 arrives, UID 3 is flagged, UID 2 marked \Deleted.
	insert(4)
	addFlags(3, imap.FlagFlagged)
	addFlags(2, imap.FlagDeleted)

	err := database.InReadSnapshot(ctx, func(snapCtx context.Context) error {
		// First query fixes the PostgreSQL REPEATABLE READ MVCC snapshot.
		summary, err := database.GetMailboxSummary(snapCtx, mailboxID)
		require.NoError(t, err)
		require.Equal(t, 4, summary.NumMessages)
		require.Equal(t, 2, summary.UnseenCount)

		// Concurrent sessions overwrite UID 3 in place (adding \Seen, \Answered, and a new
		// keyword), mark+expunge newly delivered UID 4, expunge UID 2, and deliver UID 5.
		addFlags(3, imap.FlagSeen, imap.FlagAnswered, imap.Flag("$AfterSummary"))
		addFlags(4, imap.FlagDeleted)
		write(func(tx pgx.Tx) error {
			_, err := database.ExpungeMessageUIDs(ctx, tx, mailboxID, 2, 4)
			return err
		})
		insert(5)

		unseenSeq, err := database.GetFirstUnseenSeqNum(snapCtx, mailboxID)
		require.NoError(t, err)
		assert.Equal(t, uint32(3), unseenSeq, "UID 3 must still be the first unseen message in the snapshot")

		customFlags, err := database.GetUniqueCustomFlagsForMailbox(snapCtx, mailboxID)
		require.NoError(t, err)
		assert.NotContains(t, customFlags, "$AfterSummary", "keyword added after snapshot must not leak")

		known := imap.UIDSet{imap.UIDRange{Start: 1, Stop: 4}}
		active, err := database.GetActiveUIDsInSet(snapCtx, mailboxID, known)
		require.NoError(t, err)
		assert.Equal(t, []imap.UID{1, 2, 3, 4}, active)

		vanished, err := database.GetVanishedUIDs(snapCtx, mailboxID, since, summary.HighestModSeq)
		require.NoError(t, err)
		assert.Empty(t, vanished)

		changed, err := database.GetMessagesChangedSince(snapCtx, mailboxID, since)
		require.NoError(t, err)
		require.Len(t, changed, 3, "UIDs 2, 3, and 4 must all be reported as changed in the snapshot")

		assert.Equal(t, imap.UID(2), changed[0].UID)
		assert.Equal(t, uint32(2), changed[0].SeqNum)
		assert.ElementsMatch(t, []imap.Flag{imap.FlagSeen, imap.FlagDeleted}, changed[0].Flags)
		assert.LessOrEqual(t, changed[0].ModSeq, summary.HighestModSeq)

		assert.Equal(t, imap.UID(3), changed[1].UID)
		assert.Equal(t, uint32(3), changed[1].SeqNum)
		assert.ElementsMatch(t, []imap.Flag{imap.FlagFlagged}, changed[1].Flags)
		assert.LessOrEqual(t, changed[1].ModSeq, summary.HighestModSeq)

		assert.Equal(t, imap.UID(4), changed[2].UID)
		assert.Equal(t, uint32(4), changed[2].SeqNum)
		assert.Empty(t, changed[2].Flags)
		assert.LessOrEqual(t, changed[2].ModSeq, summary.HighestModSeq)

		return nil
	})
	require.NoError(t, err)
}

func TestInReadSavepointRecoversStatementError(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, database, fmt.Sprintf("savepoint_%d@example.com", ts), "password")
	mailboxID := createTestMailbox(t, database, accountID, fmt.Sprintf("Savepoint_%d", ts))

	err := database.InReadSnapshot(ctx, func(snapCtx context.Context) error {
		summaryBefore, err := database.GetMailboxSummary(snapCtx, mailboxID)
		require.NoError(t, err)

		spErr := InReadSavepoint(snapCtx, func(spCtx context.Context) error {
			var n int
			return database.readQuerier(spCtx).QueryRow(spCtx, "SELECT 1 / 0").Scan(&n)
		})
		require.Error(t, spErr)
		require.NotErrorIs(t, spErr, ErrReadSnapshotAborted)

		summaryAfter, err := database.GetMailboxSummary(snapCtx, mailboxID)
		require.NoError(t, err, "outer snapshot transaction must remain usable after savepoint rollback")
		assert.Equal(t, summaryBefore.UIDNext, summaryAfter.UIDNext)
		return nil
	})
	require.NoError(t, err)
}

func TestInReadSnapshotHonoursMasterDBPin(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	master := setupTestDatabase(t)
	defer master.Close()
	ctx := context.Background()

	ts := time.Now().UnixNano()
	accountID := createTestAccount(t, master, fmt.Sprintf("snapshotpin_%d@example.com", ts), "password")
	mailboxName := fmt.Sprintf("SnapshotPin_%d", ts)
	mailboxID := createTestMailbox(t, master, accountID, mailboxName)

	schema := fmt.Sprintf("snapshot_pin_replica_%d", ts)
	_, err := master.GetWritePool().Exec(ctx, fmt.Sprintf("CREATE SCHEMA %s", schema))
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = master.GetWritePool().Exec(context.Background(), fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schema))
	})
	for _, table := range []string{"mailboxes", "mailbox_stats", "messages", "message_state"} {
		_, err := master.GetWritePool().Exec(ctx, fmt.Sprintf("CREATE TABLE %s.%s AS SELECT * FROM public.%s WHERE false", schema, table, table))
		require.NoError(t, err)
	}

	tx, err := master.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUIDForPoll(t, master, ctx, tx, accountID, mailboxID, mailboxName, 1, nil)
	require.NoError(t, tx.Commit(ctx))

	poolCfg := master.GetWritePool().Config().Copy()
	poolCfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	laggingPool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	require.NoError(t, err)
	defer laggingPool.Close()

	splitDB := &Database{
		WritePool: master.GetWritePool(),
		ReadPool:  laggingPool,
	}

	pinnedCtx := context.WithValue(ctx, consts.UseMasterDBKey, true)
	err = splitDB.InReadSnapshot(pinnedCtx, func(snapCtx context.Context) error {
		summary, err := splitDB.GetMailboxSummary(snapCtx, mailboxID)
		require.NoError(t, err)
		assert.Equal(t, 1, summary.NumMessages)
		return nil
	})
	require.NoError(t, err)
}
