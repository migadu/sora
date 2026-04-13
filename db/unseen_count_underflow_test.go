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
