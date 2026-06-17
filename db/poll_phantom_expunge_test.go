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

// TestPollDoesNotEmitPhantomExpunge is a regression test for the IMAP sync desync that made Outlook
// stop showing new mail. A message that is BOTH created and expunged within a single poll window was
// never sent to the client (no EXISTS), yet PollMailbox reported it as an EXPUNGE. Applying an EXPUNGE
// for a never-seen message shifts the client's sequence numbers against the wrong message and desyncs
// the mailbox tracker. After the fix:
//   - a create+expunge-in-window message is NOT reported at all,
//   - a genuinely new (still-active) message IS reported as a non-expunge update,
//   - a client-known message expunged in-window IS reported with its correct client-view seq number.
func TestPollDoesNotEmitPhantomExpunge(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	email := fmt.Sprintf("test_phantom_expunge_%d@example.com", time.Now().UnixNano())
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.CreateAccount(ctx, tx, CreateAccountRequest{Email: email, Password: "password", IsPrimary: true, HashType: "bcrypt"})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	accountID, err := db.GetAccountIDByAddress(ctx, email)
	require.NoError(t, err)

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "INBOX", nil))
	require.NoError(t, tx.Commit(ctx))
	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	mailboxID := mailbox.ID

	// Client-known baseline: 3 messages (UIDs 1,2,3). sinceModSeq captures the client's last-seen state.
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 1, nil)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 2, nil)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 3, nil)
	require.NoError(t, tx.Commit(ctx))
	sinceModSeq := getHighestModSeq(t, db, ctx, mailboxID)

	// In-window activity (all created/expunged after sinceModSeq):
	//   UID 4: genuinely new, stays active            -> must be reported (new)
	//   UID 5: created then expunged in-window         -> phantom, must NOT be reported
	//   UID 2: client-known, expunged in-window        -> must be reported as expunge at seq 2
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 4, nil)
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 5, nil)
	require.NoError(t, tx.Commit(ctx))

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.ExpungeMessageUIDs(ctx, tx, mailboxID, imap.UID(5)) // phantom: created+expunged in-window
	require.NoError(t, err)
	_, err = db.ExpungeMessageUIDs(ctx, tx, mailboxID, imap.UID(2)) // legit: client-known, expunged in-window
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	poll, err := db.PollMailbox(ctx, mailboxID, sinceModSeq)
	require.NoError(t, err)

	byUID := make(map[imap.UID]MessageUpdate)
	for _, u := range poll.Updates {
		byUID[u.UID] = u
	}

	// Phantom (UID 5) must not appear at all.
	_, hasPhantom := byUID[5]
	assert.False(t, hasPhantom, "UID 5 (created+expunged within the poll window) must not be reported")

	// New message (UID 4) reported as a non-expunge update.
	u4, has4 := byUID[4]
	require.True(t, has4, "UID 4 (new active message) must be reported")
	assert.False(t, u4.IsExpunge, "UID 4 must be a new/active update, not an expunge")

	// Client-known message expunged in-window (UID 2) reported with correct client-view seq number.
	u2, has2 := byUID[2]
	require.True(t, has2, "UID 2 (client-known, expunged in-window) must be reported")
	assert.True(t, u2.IsExpunge, "UID 2 must be reported as an expunge")
	assert.Equal(t, uint32(2), u2.SeqNum, "UID 2 expunge seq must be its position in the client's view (2), not shifted by in-window messages")
}

// TestPollDoesNotEmitPhantomExpungeDensePath exercises the same invariant through the DENSE poll path
// (len(rawUpdates) > 50), which streams sequence numbers in a single ORDER BY uid pass instead of the
// per-update batch. A create+expunge-in-window phantom must not appear and must not shift the seq
// number of a client-known expunge.
func TestPollDoesNotEmitPhantomExpungeDensePath(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	email := fmt.Sprintf("test_phantom_expunge_dense_%d@example.com", time.Now().UnixNano())
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.CreateAccount(ctx, tx, CreateAccountRequest{Email: email, Password: "password", IsPrimary: true, HashType: "bcrypt"})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	accountID, err := db.GetAccountIDByAddress(ctx, email)
	require.NoError(t, err)

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "INBOX", nil))
	require.NoError(t, tx.Commit(ctx))
	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)
	mailboxID := mailbox.ID

	// Baseline: 60 client-known messages (UIDs 1..60).
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	for uid := uint32(1); uid <= 60; uid++ {
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", uid, nil)
	}
	require.NoError(t, tx.Commit(ctx))
	sinceModSeq := getHighestModSeq(t, db, ctx, mailboxID)

	// In-window: 60 genuinely new active messages (UIDs 61..120) -> >50 updates forces the dense path.
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	for uid := uint32(61); uid <= 120; uid++ {
		insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", uid, nil)
	}
	// Phantom: created and expunged within the window.
	insertTestMessageWithUIDForPoll(t, db, ctx, tx, accountID, mailboxID, "INBOX", 121, nil)
	require.NoError(t, tx.Commit(ctx))

	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = db.ExpungeMessageUIDs(ctx, tx, mailboxID, imap.UID(121)) // phantom
	require.NoError(t, err)
	_, err = db.ExpungeMessageUIDs(ctx, tx, mailboxID, imap.UID(30)) // client-known, expunged in-window
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	poll, err := db.PollMailbox(ctx, mailboxID, sinceModSeq)
	require.NoError(t, err)
	require.Greater(t, len(poll.Updates), 50, "precondition: must exercise the dense path")

	byUID := make(map[imap.UID]MessageUpdate)
	for _, u := range poll.Updates {
		byUID[u.UID] = u
	}

	_, hasPhantom := byUID[121]
	assert.False(t, hasPhantom, "phantom UID 121 must not be reported (dense path)")

	u30, has30 := byUID[30]
	require.True(t, has30, "client-known expunge UID 30 must be reported")
	assert.True(t, u30.IsExpunge, "UID 30 must be an expunge")
	assert.Equal(t, uint32(30), u30.SeqNum, "UID 30 expunge seq must be its client-view position (30)")
}
