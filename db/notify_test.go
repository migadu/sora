package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/go-imap"
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

// TestModSeqWindowSpansOneWrite: InsertMessage, CopyMessages and MoveMessages
// measure the destination's highest mod-sequence right before and right after
// their own change to it, inside their transaction, when the context asks for
// that mailbox, and leave a window for another mailbox alone.
func TestModSeqWindowSpansOneWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}
	db, accountID, inboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	destID := createTestMailbox(t, db, accountID, "WindowDest")

	var bs imap.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain", Size: 100}
	base := time.Now().UnixNano()
	n := 0
	insert := func(ctx context.Context, tx pgx.Tx, mailboxID int64, mailboxName string) (imap.UID, error) {
		n++
		hash := fmt.Sprintf("modseqwindow-%d-%d", base, n)
		_, uid, err := db.InsertMessage(ctx, tx, &InsertMessageOptions{
			AccountID: accountID, MailboxID: mailboxID, MailboxName: mailboxName,
			S3Domain: "example.com", S3Localpart: "modseqwindow", ContentHash: hash,
			MessageID: hash + "@example.com", InternalDate: time.Now(), Size: 100,
			Subject: "window", BodyStructure: &bs,
		}, PendingUpload{InstanceID: "test", ContentHash: hash, Size: 100, AccountID: accountID})
		return imap.UID(uid), err
	}
	// write runs fn in a transaction of its own, in a context asking for
	// the destination's window, and returns the window.
	write := func(t *testing.T, fn func(ctx context.Context, tx pgx.Tx) error) ModSeqWindow {
		t.Helper()
		w := &ModSeqWindow{MailboxID: destID}
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		require.NoError(t, fn(WithModSeqWindow(ctx, w), tx))
		require.NoError(t, tx.Commit(ctx))
		return *w
	}

	var sources []imap.UID
	other := write(t, func(ctx context.Context, tx pgx.Tx) error {
		for range 2 {
			uid, err := insert(ctx, tx, inboxID, "INBOX")
			if err != nil {
				return err
			}
			sources = append(sources, uid)
		}
		return nil
	})
	assert.False(t, other.Measured, "a write into another mailbox measured the window: %+v", other)

	for _, tc := range []struct {
		name  string
		write func(ctx context.Context, tx pgx.Tx) error
	}{
		{"InsertMessage", func(ctx context.Context, tx pgx.Tx) error {
			_, err := insert(ctx, tx, destID, "WindowDest")
			return err
		}},
		{"CopyMessages", func(ctx context.Context, tx pgx.Tx) error {
			_, _, err := db.CopyMessages(ctx, tx, &[]imap.UID{sources[0]}, inboxID, destID, accountID, "example.com", "modseqwindow", "test", nil, nil)
			return err
		}},
		{"MoveMessages", func(ctx context.Context, tx pgx.Tx) error {
			_, err := db.MoveMessages(ctx, tx, &[]imap.UID{sources[1]}, inboxID, destID, accountID, "example.com", "modseqwindow", "test", nil, nil)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := getHighestModSeq(t, db, ctx, destID)
			w := write(t, tc.write)
			after := getHighestModSeq(t, db, ctx, destID)
			assert.True(t, w.Measured)
			assert.Equal(t, before, w.Before, "Before")
			assert.Equal(t, after, w.After, "After")
			assert.Greater(t, w.After, w.Before)
		})
	}
}
