package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The hard delete of a mailbox used to be one transaction whose size was the mailbox's
// size — 16s for 100k messages, 32s for 200k — against a fixed administrative deadline.
// Past roughly 280k messages it could never commit, and since it rolled back whole, that
// mailbox became a permanent poison pill: retried every cleaner cycle, never progressing.
//
// PurgeMailboxStep replaces it with bounded, resumable steps. This pins the three
// properties the cleaner depends on:
//  1. a step expunges at most `limit` messages and reports "not done"
//  2. the mailbox row survives every step that still found live messages — deleting it
//     early would strand them with mailbox_id NULL and expunged_at NULL (live, invisible)
//  3. committed steps stay committed, so an interrupted purge resumes instead of restarting
func TestPurgeMailboxStepIsBoundedAndGuarded(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	mailbox := createPurgeTestMailbox(t, db, accountID, "StepBox")
	const total = 3
	for i := 0; i < total; i++ {
		insertTestMessage(t, db, accountID, mailbox, "StepBox",
			fmt.Sprintf("step %d", i), fmt.Sprintf("<step-%d-%d@example.com>", i, time.Now().UnixNano()))
	}

	step := func(limit int) bool {
		t.Helper()
		tx, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		done, err := db.PurgeMailboxStep(ctx, tx, mailbox, accountID, limit)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(ctx)) // each step commits on its own
		return done
	}

	liveCount := func() int {
		t.Helper()
		var n int
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			"SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL", mailbox).Scan(&n))
		return n
	}
	mailboxRows := func() int {
		t.Helper()
		var n int
		require.NoError(t, db.GetReadPool().QueryRow(ctx,
			"SELECT COUNT(*) FROM mailboxes WHERE id = $1", mailbox).Scan(&n))
		return n
	}

	// One message per step, and the mailbox stays put while any message is still live.
	for i := total; i > 0; i-- {
		require.False(t, step(1), "a step that still found live messages must not report done")
		assert.Equal(t, i-1, liveCount(), "each step must expunge exactly one message")
		assert.Equal(t, 1, mailboxRows(), "the mailbox must not be deleted while messages are live")
	}

	// The remaining phases (dropping message_state, detaching the messages) are bounded
	// the same way, so drive to completion — the mailbox row must survive every step until
	// the very last one.
	done := false
	for i := 0; i < 50 && !done; i++ {
		assert.Equal(t, 1, mailboxRows(), "the mailbox row survives until the final step")
		done = step(1)
	}
	require.True(t, done, "the purge must complete in a bounded number of bounded steps")
	assert.Equal(t, 0, mailboxRows(), "the mailbox row is gone once everything is detached")

	var orphanedLive int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND mailbox_id IS NULL AND expunged_at IS NULL", accountID).Scan(&orphanedLive))
	assert.Equal(t, 0, orphanedLive, "no message may survive as live-but-mailboxless")
}

// A mailbox whose purge is interrupted must resume, not restart: the steps that already
// committed keep their messages expunged. This is the property that makes an arbitrarily
// large mailbox drainable across cleaner cycles.
func TestPurgeMailboxStepResumesAfterInterruption(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	mailbox := createPurgeTestMailbox(t, db, accountID, "ResumeBox")
	for i := 0; i < 4; i++ {
		insertTestMessage(t, db, accountID, mailbox, "ResumeBox",
			fmt.Sprintf("resume %d", i), fmt.Sprintf("<resume-%d-%d@example.com>", i, time.Now().UnixNano()))
	}

	// One committed step, then "crash".
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	done, err := db.PurgeMailboxStep(ctx, tx, mailbox, accountID, 2)
	require.NoError(t, err)
	require.False(t, done)
	require.NoError(t, tx.Commit(ctx))

	var expunged int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE mailbox_id = $1 AND expunged_at IS NOT NULL", mailbox).Scan(&expunged))
	require.Equal(t, 2, expunged, "the committed step's work must be durable")

	// A later cycle picks the tombstone up and finishes it.
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.DeleteMailbox(ctx, tx2, mailbox, accountID))
	require.NoError(t, tx2.Commit(ctx))

	var rows int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM mailboxes WHERE id = $1", mailbox).Scan(&rows))
	assert.Equal(t, 0, rows)

	var stamped int
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT COUNT(*) FROM messages WHERE account_id = $1 AND mailbox_path = 'ResumeBox' AND expunged_at IS NOT NULL", accountID).Scan(&stamped))
	assert.Equal(t, 4, stamped, "every message keeps the mailbox's name for restore")
}

func createPurgeTestMailbox(t *testing.T, db *Database, accountID int64, name string) int64 {
	t.Helper()
	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, name, nil))
	require.NoError(t, tx.Commit(ctx))
	mb, err := db.GetMailboxByName(ctx, accountID, name)
	require.NoError(t, err)
	return mb.ID
}

// DELETE /user/mailboxes/{name} (and `sora-admin mailbox delete`) used to hard-delete
// inline: one transaction that expunged and rewrote every message row of the mailbox,
// holding the row lock a delivery has to wait behind, and growing with the mailbox until
// it outran the request's own deadline.
//
// It now does what IMAP DELETE does — stamp deleted_at and leave the per-message work to
// the cleaner — without changing what the caller observes: the named mailbox disappears
// at once, and a child mailbox is left alone (deleting a parent has never removed its
// children; the path-prefix clause that claimed to could not match, see PurgeMailboxStep).
func TestDeleteMailboxForUserSoftDeletes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, _, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	parent := createPurgeTestMailbox(t, db, accountID, "Project")
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "Project/Notes", &parent))
	require.NoError(t, tx.Commit(ctx))
	child, err := db.GetMailboxByName(ctx, accountID, "Project/Notes")
	require.NoError(t, err)

	parentMsg := insertTestMessage(t, db, accountID, parent, "Project", "p", fmt.Sprintf("<p-%d@example.com>", time.Now().UnixNano()))
	childMsg := insertTestMessage(t, db, accountID, child.ID, "Project/Notes", "c", fmt.Sprintf("<c-%d@example.com>", time.Now().UnixNano()))

	require.NoError(t, db.DeleteMailboxForUser(ctx, accountID, "Project"))

	_, err = db.GetMailboxByName(ctx, accountID, "Project")
	assert.Error(t, err, "the deleted mailbox must be invisible immediately")

	// No per-message work happened in the request itself.
	var expungedAt *time.Time
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT expunged_at FROM messages WHERE id = $1", parentMsg).Scan(&expungedAt))
	assert.Nil(t, expungedAt, "the interactive delete must not expunge messages inline")

	// The cleaner finishes the job.
	drainPurgeUntilGone(t, db, ctx, parent)

	var path string
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT mailbox_path, expunged_at FROM messages WHERE id = $1", parentMsg).Scan(&path, &expungedAt))
	assert.Equal(t, "Project", path)
	assert.NotNil(t, expungedAt, "the sweep expunges what the interactive delete deferred")

	// The child is untouched throughout — unchanged from the synchronous implementation.
	stillThere, err := db.GetMailboxByName(ctx, accountID, "Project/Notes")
	require.NoError(t, err, "deleting a parent must not take its children")
	assert.Equal(t, child.ID, stillThere.ID)
	require.NoError(t, db.GetReadPool().QueryRow(ctx,
		"SELECT expunged_at FROM messages WHERE id = $1", childMsg).Scan(&expungedAt))
	assert.Nil(t, expungedAt, "a child mailbox's messages are not touched")
}
