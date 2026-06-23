//go:build integration
// +build integration

package db

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMailboxStatsCTERace reproduces and validates the fix for the unseen_count CTE race condition.
//
// Bug scenario (fixed in 000030_fix_mailbox_stats_race):
// 1. InsertMessage uses concurrent CTEs to insert into messages and message_state.
// 2. maintain_mailbox_stats_state trigger could execute before maintain_mailbox_stats_messages.
// 3. When message_state executed first, UPDATE mailbox_stats found 0 rows and did nothing.
// 4. Then messages trigger created the mailbox_stats row with unseen_count = 0.
// 5. Subsequent read/delete subtracted from 0, resulting in negative unseen_count.
func TestMailboxStatsCTERace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Create test account
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)

	req := CreateAccountRequest{
		Email:     fmt.Sprintf("test_cte_race_%d@example.com", time.Now().UnixNano()),
		Password:  "password",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	accountID, err := db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)

	// Create mailbox
	err = db.CreateMailbox(ctx, tx, accountID, "RaceBox", nil)
	require.NoError(t, err)
	err = tx.Commit(ctx)
	require.NoError(t, err)

	mailbox, err := db.GetMailboxByName(ctx, accountID, "RaceBox")
	require.NoError(t, err)

	getUnseenCount := func(mailboxID int64) int {
		var unseenCount int
		err := db.GetReadPool().QueryRow(ctx, "SELECT unseen_count FROM mailbox_stats WHERE mailbox_id = $1", mailboxID).Scan(&unseenCount)
		if err != nil {
			return 0
		}
		return unseenCount
	}

	// Step 1: Insert multiple messages concurrently to stress the trigger execution order
	// Using the actual InsertMessage method which uses the CTE
	var wg sync.WaitGroup
	// Even 50 messages is enough since CTE execution order is highly unpredictable
	numMessages := 50

	for i := 0; i < numMessages; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			tx2, err := db.GetWritePool().Begin(ctx)
			if err != nil {
				return
			}
			defer tx2.Rollback(ctx)

			opts := &InsertMessageOptions{
				AccountID:     accountID,
				MailboxID:     mailbox.ID,
				MailboxName:   mailbox.Name,
				S3Domain:      "example.com",
				S3Localpart:   fmt.Sprintf("test-s3-%d", idx),
				ContentHash:   fmt.Sprintf("test-hash-%d", idx),
				MessageID:     fmt.Sprintf("<msg-id-%d@example.com>", idx),
				Flags:         []imap.Flag{}, // Unseen!
				InternalDate:  time.Now(),
				Size:          1024,
				Subject:       "Test Race Subject",
				PlaintextBody: "test",
				SentDate:      time.Now(),
			}

			_, _, _ = db.InsertMessage(ctx, tx2, opts, PendingUpload{AccountID: accountID, ContentHash: opts.ContentHash})
			_ = tx2.Commit(ctx)
		}(i)
	}

	wg.Wait()

	// Step 2: Verify the unseen count exactly matches the number of messages inserted
	unseenCount := getUnseenCount(mailbox.ID)
	assert.Equal(t, numMessages, unseenCount, "Mailbox should correctly track all unseen messages despite CTE race conditions")

	// Step 3: Expunge all messages to ensure unseen count correctly zeroes out and DOES NOT go negative
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	_, err = tx3.Exec(ctx, `
		UPDATE messages
		SET expunged_at = NOW(), expunged_modseq = nextval('messages_modseq')
		WHERE mailbox_id = $1
	`, mailbox.ID)
	require.NoError(t, err)
	err = tx3.Commit(ctx)
	require.NoError(t, err)

	unseenCountAfterExpunge := getUnseenCount(mailbox.ID)
	assert.Equal(t, 0, unseenCountAfterExpunge, "Mailbox unseen count should correctly zero out after expunge, not go negative")

	t.Logf("✓ Trigger CTE race condition tested perfectly. Unseen count: %d after inserts, %d after expunge", unseenCount, unseenCountAfterExpunge)
}

// readUnseenCount returns the cached mailbox_stats.unseen_count (the denormalized
// value that STATUS/LIST serve), or 0 if the row is missing.
func readUnseenCount(ctx context.Context, t *testing.T, db *Database, mailboxID int64) int64 {
	t.Helper()
	var unseen int64
	err := db.GetReadPool().QueryRow(ctx, "SELECT unseen_count FROM mailbox_stats WHERE mailbox_id = $1", mailboxID).Scan(&unseen)
	if err != nil {
		return 0
	}
	return unseen
}

// authoritativeUnseenCount counts active, unseen messages directly from the source
// of truth — what the cache is supposed to equal.
func authoritativeUnseenCount(ctx context.Context, t *testing.T, db *Database, mailboxID int64) int64 {
	t.Helper()
	var unseen int64
	err := db.GetReadPool().QueryRow(ctx, `
		SELECT COUNT(*)
		FROM message_state ms
		JOIN messages m ON m.id = ms.message_id AND m.mailbox_id = ms.mailbox_id
		WHERE ms.mailbox_id = $1 AND (ms.flags & 1) = 0 AND m.expunged_at IS NULL
	`, mailboxID).Scan(&unseen)
	require.NoError(t, err)
	return unseen
}

// TestRecomputeMailboxUnseenHeals verifies the self-heal path: a deliberately
// corrupted (negative) cache value is restored to the authoritative count.
func TestRecomputeMailboxUnseenHeals(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	accountID, err := db.CreateAccount(ctx, tx, CreateAccountRequest{
		Email:     fmt.Sprintf("test_heal_%d@example.com", time.Now().UnixNano()),
		Password:  "password",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "HealBox", nil))
	require.NoError(t, tx.Commit(ctx))

	mailbox, err := db.GetMailboxByName(ctx, accountID, "HealBox")
	require.NoError(t, err)

	const numMessages = 7
	for i := 0; i < numMessages; i++ {
		tx2, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		opts := &InsertMessageOptions{
			AccountID: accountID, MailboxID: mailbox.ID, MailboxName: mailbox.Name,
			S3Domain: "example.com", S3Localpart: fmt.Sprintf("heal-s3-%d", i),
			ContentHash: fmt.Sprintf("heal-hash-%d", i), MessageID: fmt.Sprintf("<heal-%d@example.com>", i),
			Flags: []imap.Flag{}, InternalDate: time.Now(), Size: 1024,
			Subject: "Heal", PlaintextBody: "test", SentDate: time.Now(),
		}
		_, _, err = db.InsertMessage(ctx, tx2, opts, PendingUpload{AccountID: accountID, ContentHash: opts.ContentHash})
		require.NoError(t, err)
		require.NoError(t, tx2.Commit(ctx))
	}

	// Corrupt the cache to simulate accumulated underflow drift.
	_, err = db.GetWritePool().Exec(ctx, "UPDATE mailbox_stats SET unseen_count = -5 WHERE mailbox_id = $1", mailbox.ID)
	require.NoError(t, err)
	require.Equal(t, int64(-5), readUnseenCount(ctx, t, db, mailbox.ID))

	// Heal.
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	repaired, err := db.RecomputeMailboxUnseen(ctx, tx3, mailbox.ID)
	require.NoError(t, err)
	require.NoError(t, tx3.Commit(ctx))

	assert.Equal(t, int64(numMessages), repaired, "recompute should return the authoritative unseen count")
	assert.Equal(t, int64(numMessages), readUnseenCount(ctx, t, db, mailbox.ID), "cache should be restored to the authoritative count")
}

// TestUnseenCountConcurrentFlagExpungeRace is the regression test for the negative
// drift bug. It races mark-\Seen against EXPUNGE on the same messages from many
// concurrent transactions. The per-mailbox advisory lock (db.lockMailboxStats) makes
// the two stats triggers serialize, so the cache must stay consistent with the
// authoritative count and must never go negative. Before the fix this drifted below 0.
func TestUnseenCountConcurrentFlagExpungeRace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	accountID, err := db.CreateAccount(ctx, tx, CreateAccountRequest{
		Email:     fmt.Sprintf("test_race_fe_%d@example.com", time.Now().UnixNano()),
		Password:  "password",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "RaceFE", nil))
	require.NoError(t, tx.Commit(ctx))

	mailbox, err := db.GetMailboxByName(ctx, accountID, "RaceFE")
	require.NoError(t, err)

	// Insert unseen messages, capturing their UIDs.
	const numMessages = 150
	uids := make([]imap.UID, 0, numMessages)
	for i := 0; i < numMessages; i++ {
		tx2, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		opts := &InsertMessageOptions{
			AccountID: accountID, MailboxID: mailbox.ID, MailboxName: mailbox.Name,
			S3Domain: "example.com", S3Localpart: fmt.Sprintf("race-s3-%d", i),
			ContentHash: fmt.Sprintf("race-hash-%d", i), MessageID: fmt.Sprintf("<race-%d@example.com>", i),
			Flags: []imap.Flag{}, InternalDate: time.Now(), Size: 1024,
			Subject: "Race", PlaintextBody: "test", SentDate: time.Now(),
		}
		_, uid, err := db.InsertMessage(ctx, tx2, opts, PendingUpload{AccountID: accountID, ContentHash: opts.ContentHash})
		require.NoError(t, err)
		require.NoError(t, tx2.Commit(ctx))
		uids = append(uids, imap.UID(uid))
	}

	require.Equal(t, int64(numMessages), readUnseenCount(ctx, t, db, mailbox.ID), "all inserted messages should be unseen")

	// For every message, race a mark-\Seen against an EXPUNGE in separate concurrent
	// transactions. The advisory lock must serialize their trigger bookkeeping.
	var wg sync.WaitGroup
	runInTx := func(fn func(tx pgx.Tx) error) {
		defer wg.Done()
		tx, err := db.GetWritePool().Begin(ctx)
		if err != nil {
			return
		}
		if err := fn(tx); err != nil {
			_ = tx.Rollback(ctx)
			return
		}
		_ = tx.Commit(ctx)
	}

	for _, uid := range uids {
		uid := uid
		wg.Add(2)
		go runInTx(func(tx pgx.Tx) error {
			_, err := db.AddMessageFlagsBatch(ctx, tx, []imap.UID{uid}, mailbox.ID, []imap.Flag{imap.FlagSeen})
			return err
		})
		go runInTx(func(tx pgx.Tx) error {
			_, err := db.ExpungeMessageUIDs(ctx, tx, mailbox.ID, uid)
			return err
		})
	}
	wg.Wait()

	cached := readUnseenCount(ctx, t, db, mailbox.ID)
	authoritative := authoritativeUnseenCount(ctx, t, db, mailbox.ID)

	assert.GreaterOrEqual(t, cached, int64(0), "unseen_count must never go negative")
	assert.Equal(t, authoritative, cached, "cached unseen_count must match the authoritative count after concurrent flag/expunge races")
	t.Logf("✓ Concurrent flag/expunge race: cached=%d authoritative=%d", cached, authoritative)
}

// TestUnseenCountUserAPIFlagExpungeRace is the regression test for the User API
// flag path. UpdateMessageFlags (server/userapi) manages its own transaction and
// previously did NOT lock the mailbox row, so a User API "mark \Seen" racing an
// IMAP/POP3 EXPUNGE on the same message double-counted the "no longer unseen"
// event and drifted unseen_count negative — the same bug the IMAP paths guard
// against. With the lockMailboxStats guard added to UpdateMessageFlags, the cache
// must stay consistent with the authoritative count and never go negative.
func TestUnseenCountUserAPIFlagExpungeRace(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	accountID, err := db.CreateAccount(ctx, tx, CreateAccountRequest{
		Email:     fmt.Sprintf("test_uapi_race_%d@example.com", time.Now().UnixNano()),
		Password:  "password",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "UApiRace", nil))
	require.NoError(t, tx.Commit(ctx))

	mailbox, err := db.GetMailboxByName(ctx, accountID, "UApiRace")
	require.NoError(t, err)

	// Insert unseen messages, capturing both the DB message id (used by the User
	// API) and the UID (used by EXPUNGE).
	type msgRef struct {
		id  int64
		uid imap.UID
	}
	const numMessages = 150
	refs := make([]msgRef, 0, numMessages)
	for i := 0; i < numMessages; i++ {
		tx2, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)
		opts := &InsertMessageOptions{
			AccountID: accountID, MailboxID: mailbox.ID, MailboxName: mailbox.Name,
			S3Domain: "example.com", S3Localpart: fmt.Sprintf("uapi-s3-%d", i),
			ContentHash: fmt.Sprintf("uapi-hash-%d", i), MessageID: fmt.Sprintf("<uapi-%d@example.com>", i),
			Flags: []imap.Flag{}, InternalDate: time.Now(), Size: 1024,
			Subject: "UApiRace", PlaintextBody: "test", SentDate: time.Now(),
		}
		id, uid, err := db.InsertMessage(ctx, tx2, opts, PendingUpload{AccountID: accountID, ContentHash: opts.ContentHash})
		require.NoError(t, err)
		require.NoError(t, tx2.Commit(ctx))
		refs = append(refs, msgRef{id: id, uid: imap.UID(uid)})
	}

	require.Equal(t, int64(numMessages), readUnseenCount(ctx, t, db, mailbox.ID), "all inserted messages should be unseen")

	// For every message, race a User API "mark \Seen" (UpdateMessageFlags, which
	// opens its own transaction) against an IMAP EXPUNGE. The mailbox-row lock in
	// UpdateMessageFlags must serialize its trigger bookkeeping with the expunge.
	var wg sync.WaitGroup
	for _, ref := range refs {
		ref := ref
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = db.UpdateMessageFlags(ctx, accountID, ref.id, []string{"\\Seen"}, nil)
		}()
		go func() {
			defer wg.Done()
			tx, err := db.GetWritePool().Begin(ctx)
			if err != nil {
				return
			}
			if _, err := db.ExpungeMessageUIDs(ctx, tx, mailbox.ID, ref.uid); err != nil {
				_ = tx.Rollback(ctx)
				return
			}
			_ = tx.Commit(ctx)
		}()
	}
	wg.Wait()

	cached := readUnseenCount(ctx, t, db, mailbox.ID)
	authoritative := authoritativeUnseenCount(ctx, t, db, mailbox.ID)

	assert.GreaterOrEqual(t, cached, int64(0), "unseen_count must never go negative")
	assert.Equal(t, authoritative, cached, "cached unseen_count must match the authoritative count after concurrent User API flag / expunge races")
	t.Logf("✓ Concurrent User API flag / expunge race: cached=%d authoritative=%d", cached, authoritative)
}
