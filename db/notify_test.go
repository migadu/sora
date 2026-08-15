package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMailboxStatsPolling covers the NOTIFY fan-in queries: PollMailboxStats
// (change detection over a set of mailboxes with one monotonic cursor) and
// GetMailboxesStats (bootstrap, including mailboxes without any messages).
func TestMailboxStatsPolling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	// Setup: one account, three mailboxes (INBOX, Archive, Empty).
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	testEmail := fmt.Sprintf("test_notify_%d@example.com", time.Now().UnixNano())
	req := CreateAccountRequest{Email: testEmail, Password: "password", IsPrimary: true, HashType: "bcrypt"}
	_, err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	mailboxIDs := make(map[string]int64)
	for _, name := range []string{"INBOX", "Archive", "Empty"} {
		tx, err = db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		require.NoError(t, db.CreateMailbox(ctx, tx, accountID, name, nil))
		require.NoError(t, tx.Commit(ctx))
		mbox, err := db.GetMailboxByName(ctx, accountID, name)
		require.NoError(t, err)
		mailboxIDs[name] = mbox.ID
	}
	allIDs := []int64{mailboxIDs["INBOX"], mailboxIDs["Archive"], mailboxIDs["Empty"]}

	t.Run("BootstrapIncludesEmptyMailboxes", func(t *testing.T) {
		rows, err := db.GetMailboxesStats(ctx, allIDs)
		require.NoError(t, err)
		// Every mailbox is returned, even without a mailbox_stats row yet:
		// the initial STATUS responses of NOTIFY SET STATUS are due for
		// empty mailboxes too (RFC 5465 section 3.1).
		assert.Len(t, rows, 3)
		for _, row := range rows {
			assert.Zero(t, row.MessageCount)
		}
	})

	t.Run("EmptyIDListReturnsNothing", func(t *testing.T) {
		rows, err := db.PollMailboxStats(ctx, nil, 0)
		require.NoError(t, err)
		assert.Empty(t, rows)
		rows, err = db.GetMailboxesStats(ctx, nil)
		require.NoError(t, err)
		assert.Empty(t, rows)
	})

	// Deliver one message into Archive.
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxIDs["Archive"], "Archive", 1, nil)
	require.NoError(t, tx.Commit(ctx))

	var cursor uint64
	t.Run("DeltaDetection", func(t *testing.T) {
		rows, err := db.PollMailboxStats(ctx, allIDs, 0)
		require.NoError(t, err)
		// Only Archive has changes past modseq 0 (INBOX and Empty have no
		// messages, hence no mailbox_stats rows or zero modseq).
		require.Len(t, rows, 1)
		row := rows[0]
		assert.Equal(t, mailboxIDs["Archive"], row.MailboxID)
		assert.Equal(t, uint32(1), row.MessageCount)
		assert.Equal(t, uint32(1), row.HighestUID)
		assert.Greater(t, row.HighestModSeq, uint64(0))
		cursor = row.HighestModSeq
	})

	t.Run("CursorSuppressesSeenChanges", func(t *testing.T) {
		rows, err := db.PollMailboxStats(ctx, allIDs, cursor)
		require.NoError(t, err)
		assert.Empty(t, rows, "no rows expected when polling from the current cursor")
	})

	t.Run("NewChangeAdvancesPastCursor", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxIDs["INBOX"], "INBOX", 1, nil)
		require.NoError(t, tx.Commit(ctx))

		rows, err := db.PollMailboxStats(ctx, allIDs, cursor)
		require.NoError(t, err)
		require.Len(t, rows, 1)
		assert.Equal(t, mailboxIDs["INBOX"], rows[0].MailboxID)
		assert.Greater(t, rows[0].HighestModSeq, cursor,
			"modseqs come from the global sequence, so a later change in another mailbox must sort above the cursor")
	})

	t.Run("SoftDeletedMailboxExcluded", func(t *testing.T) {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		require.NoError(t, db.SoftDeleteMailbox(ctx, tx, mailboxIDs["Archive"], accountID))
		require.NoError(t, tx.Commit(ctx))

		rows, err := db.PollMailboxStats(ctx, allIDs, 0)
		require.NoError(t, err)
		for _, row := range rows {
			assert.NotEqual(t, mailboxIDs["Archive"], row.MailboxID, "soft-deleted mailbox must not be reported")
		}
		rows, err = db.GetMailboxesStats(ctx, allIDs)
		require.NoError(t, err)
		for _, row := range rows {
			assert.NotEqual(t, mailboxIDs["Archive"], row.MailboxID, "soft-deleted mailbox must not be reported")
		}
	})
}
