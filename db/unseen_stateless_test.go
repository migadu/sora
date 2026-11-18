package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUnseenCountsIncludeMessageWithoutState covers #1949: a message with no
// message_state row (left by older builds) has no flags, so SEARCH UNSEEN matches it
// (#1899) and every unseen count must count it too: STATUS UNSEEN and the User API
// mailbox list (both mailbox_stats.unseen_count, via GetMailboxSummary and
// GetMailboxSummariesBatch), SELECT's first unseen message (GetFirstUnseenSeqNum), and
// the recount that repairs a cached count (RecomputeMailboxUnseen).
func TestUnseenCountsIncludeMessageWithoutState(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupSearchTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	now := time.Now()

	insert := func(uid uint32, flags []imap.Flag) int64 {
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		subject := fmt.Sprintf("Unseen %d", uid)
		msg := "From: a@example.com\r\nTo: b@example.com\r\nSubject: " + subject + "\r\n\r\nBody\r\n"
		id, _, err := db.InsertMessageFromImporter(ctx, tx, &InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailboxID,
			MailboxName:   "INBOX",
			Flags:         flags,
			PreservedUID:  &uid,
			InternalDate:  now,
			SentDate:      now,
			Subject:       subject,
			MessageID:     fmt.Sprintf("<unseen-stateless-%d@example.com>", uid),
			Size:          int64(len(msg)),
			PlaintextBody: msg,
		})
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx))
		return id
	}

	// UID 1 loses its message_state row, UID 2 is unseen with a row, UID 3 is seen.
	stateless := insert(1, nil)
	insert(2, nil)
	insert(3, []imap.Flag{imap.FlagSeen})
	_, err := db.GetWritePool().Exec(ctx, `DELETE FROM message_state WHERE message_id = $1`, stateless)
	require.NoError(t, err)

	uids, err := db.SearchMessagesWithCriteria(ctx, mailboxID, accountID, &imap.SearchCriteria{NotFlag: []imap.Flag{imap.FlagSeen}}, 0, 0)
	require.NoError(t, err)
	require.Len(t, uids, 2, "SEARCH UNSEEN matches UID 1 and UID 2 (#1899)")

	assertUnseen := func(what string) {
		t.Helper()
		summary, err := db.GetMailboxSummary(ctx, mailboxID)
		require.NoError(t, err)
		assert.Equal(t, 2, summary.UnseenCount, "%s: STATUS UNSEEN (GetMailboxSummary)", what)
		batch, err := db.GetMailboxSummariesBatch(ctx, []int64{mailboxID})
		require.NoError(t, err)
		assert.Equal(t, 2, batch[mailboxID].UnseenCount, "%s: User API mailbox unseen (GetMailboxSummariesBatch)", what)
		first, err := db.GetFirstUnseenSeqNum(ctx, mailboxID)
		require.NoError(t, err)
		assert.Equal(t, uint32(1), first, "%s: SELECT [UNSEEN n] is the stateless UID 1", what)
	}
	assertUnseen("after the state row is deleted")

	// A cache an older build maintained did not count the stateless message; the recount
	// (repair-unseen --apply, the negative self-heal) counts it.
	_, err = db.GetWritePool().Exec(ctx, `UPDATE mailbox_stats SET unseen_count = 1 WHERE mailbox_id = $1`, mailboxID)
	require.NoError(t, err)
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	recounted, err := db.RecomputeMailboxUnseen(ctx, tx, mailboxID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	assert.Equal(t, int64(2), recounted, "RecomputeMailboxUnseen")
	assertUnseen("after the recount")

	// Expunging the stateless message takes it out of the count again.
	_, err = db.GetWritePool().Exec(ctx, `UPDATE messages SET expunged_at = now(), expunged_modseq = nextval('messages_modseq') WHERE id = $1`, stateless)
	require.NoError(t, err)
	summary, err := db.GetMailboxSummary(ctx, mailboxID)
	require.NoError(t, err)
	assert.Equal(t, 1, summary.UnseenCount, "after expunging the stateless message")
	first, err := db.GetFirstUnseenSeqNum(ctx, mailboxID)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), first, "UID 2 is now the first message and unseen")
}
