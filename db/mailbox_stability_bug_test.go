package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCustomFlagUpdateHighestModSeq(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	// Setup account and mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	testEmail := fmt.Sprintf("test_custom_flags_%d@example.com", time.Now().UnixNano())
	req := CreateAccountRequest{Email: testEmail, Password: "password", IsPrimary: true, HashType: "bcrypt"}
	_, err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, "INBOX", nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	mailboxID := mailbox.ID

	// Insert a test message
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 1, nil)
	require.NoError(t, tx.Commit(ctx))

	// Get modseq after insertion
	modSeqBefore := getHighestModSeq(t, db, ctx, mailboxID)

	// Update only custom flags on the message
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	_, _, err = db.AddMessageFlags(ctx, tx, 1, mailboxID, []imap.Flag{"my-custom-flag"})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	// Get modseq after custom flag update
	modSeqAfter := getHighestModSeq(t, db, ctx, mailboxID)

	assert.Greater(t, modSeqAfter, modSeqBefore, "highest_modseq on mailbox_stats must increase when only custom flags are updated")
}

func TestPollAndFetchSequenceWithStaleMessageCount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	// Setup account and mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	testEmail := fmt.Sprintf("test_stale_count_%d@example.com", time.Now().UnixNano())
	req := CreateAccountRequest{Email: testEmail, Password: "password", IsPrimary: true, HashType: "bcrypt"}
	_, err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, "INBOX", nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	mailboxID := mailbox.ID

	// Insert 5 test messages (UIDs 10, 20, 30, 40, 50)
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 10, nil)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 20, nil)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 30, nil)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 40, nil)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 50, nil)
	require.NoError(t, tx.Commit(ctx))

	// Get current stats to verify they are initially correct
	var initialCount int
	err = db.GetReadPool().QueryRow(ctx, "SELECT message_count FROM mailbox_stats WHERE mailbox_id = $1", mailboxID).Scan(&initialCount)
	require.NoError(t, err)
	require.Equal(t, 5, initialCount)

	// Manually set message_count to 3 in mailbox_stats to simulate a lagging/stale cache
	_, err = db.GetWritePool().Exec(ctx, "UPDATE mailbox_stats SET message_count = 3 WHERE mailbox_id = $1", mailboxID)
	require.NoError(t, err)

	// Verify it was updated to 3
	var updatedCount int
	err = db.GetReadPool().QueryRow(ctx, "SELECT message_count FROM mailbox_stats WHERE mailbox_id = $1", mailboxID).Scan(&updatedCount)
	require.NoError(t, err)
	require.Equal(t, 3, updatedCount)

	// 1. Verify sequence hydration via StreamMessagesByNumSet (which calls hydrateSequencesCore)
	// We fetch UIDs 40 and 50. Since these are in the second half of the mailbox,
	// they should trigger the backward sweep.
	uidSet := imap.UIDSet{
		imap.UIDRange{Start: 40, Stop: 50},
	}
	messages, err := db.GetMessagesByNumSet(ctx, mailboxID, uidSet)
	require.NoError(t, err)
	require.Len(t, messages, 2)

	// Check if sequence numbers are correct:
	// Total messages in mailbox = 5
	// Message 4 (UID 40) should have sequence number 4.
	// Message 5 (UID 50) should have sequence number 5.
	// If the stale cached count (3) is used, they will be shifted (sequence 2 and 3).
	var msg40, msg50 Message
	for _, msg := range messages {
		if msg.UID == 40 {
			msg40 = msg
		} else if msg.UID == 50 {
			msg50 = msg
		}
	}
	assert.Equal(t, uint32(4), msg40.Seq, "UID 40 sequence number must be 4, regardless of stale cached count")
	assert.Equal(t, uint32(5), msg50.Seq, "UID 50 sequence number must be 5, regardless of stale cached count")

	// 2. Verify sequence hydration via PollMailbox
	// We get the modseq from before we add flags to UID 50
	modSeqBefore := getHighestModSeq(t, db, ctx, mailboxID)

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	_, _, err = db.AddMessageFlags(ctx, tx, 50, mailboxID, []imap.Flag{imap.FlagSeen})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	// In order to make sure the poll query runs backward sweep, we simulate stale cache again.
	// Bumping the flags will trigger the triggers which update mailbox_stats.message_count back to 5.
	// We manually set it back to 3 to force the stale cache path in PollMailbox.
	_, err = db.GetWritePool().Exec(ctx, "UPDATE mailbox_stats SET message_count = 3 WHERE mailbox_id = $1", mailboxID)
	require.NoError(t, err)

	poll, err := db.PollMailbox(ctx, mailboxID, modSeqBefore)
	require.NoError(t, err)
	require.Len(t, poll.Updates, 1)
	update := poll.Updates[0]
	assert.Equal(t, imap.UID(50), update.UID)
	assert.Equal(t, uint32(5), update.SeqNum, "PollMailbox sequence number for UID 50 must be 5, regardless of stale cached count")
}

// TestPollExpungeSequenceWithStaleMessageCount covers the EXPUNGE backward-count
// branch of PollMailbox (the most intricate formula:
// SeqNum = (activeCount + expungedSinceModSeq) - countAfter). A high-UID message is
// expunged so the backward path is taken, and mailbox_stats.message_count is forced
// stale to prove the EXPUNGE sequence number no longer depends on the cached counter.
func TestPollExpungeSequenceWithStaleMessageCount(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	// Setup account and mailbox
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	testEmail := fmt.Sprintf("test_poll_expunge_%d@example.com", time.Now().UnixNano())
	req := CreateAccountRequest{Email: testEmail, Password: "password", IsPrimary: true, HashType: "bcrypt"}
	_, err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	err = db.CreateMailbox(ctx, tx, accountID, "INBOX", nil)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	mailboxID := mailbox.ID

	// Insert 5 test messages (UIDs 10, 20, 30, 40, 50).
	// highest_uid = 50, so the backward sweep midpoint is 25.
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 10, nil)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 20, nil)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 30, nil)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 40, nil)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 50, nil)
	require.NoError(t, tx.Commit(ctx))

	// Client's last-known modseq: the state where all 5 messages are visible.
	// UID 50 is at sequence position 5 in that view.
	modSeqBefore := getHighestModSeq(t, db, ctx, mailboxID)

	// Expunge the highest UID (50). It is > midpoint (25), so PollMailbox takes the
	// EXPUNGE backward-count branch. After this, 4 messages remain active.
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = db.ExpungeMessageUIDs(ctx, tx, mailboxID, imap.UID(50))
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	// Force a stale cache: the expunge trigger set message_count to 4; corrupt it to 2.
	// The fix computes the count live, so this must NOT affect the reported sequence number.
	// (The pre-fix code used this cached value and would report SeqNum 3 instead of 5.)
	_, err = db.GetWritePool().Exec(ctx, "UPDATE mailbox_stats SET message_count = 2 WHERE mailbox_id = $1", mailboxID)
	require.NoError(t, err)

	poll, err := db.PollMailbox(ctx, mailboxID, modSeqBefore)
	require.NoError(t, err)
	require.Len(t, poll.Updates, 1)
	update := poll.Updates[0]
	assert.Equal(t, imap.UID(50), update.UID)
	assert.True(t, update.IsExpunge, "UID 50 update must be an expunge")
	assert.Equal(t, uint32(5), update.SeqNum, "EXPUNGE sequence number for UID 50 must be 5 (its position in the client's view), regardless of stale cached count")
}
