package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/require"
)

// BenchmarkHydrateMessageSequences tests the performance of O(1) sequence hydration
// on a mailbox containing 100,000 active messages.
func BenchmarkHydrateMessageSequences(b *testing.B) {
	db := setupTestDatabase(b)
	defer db.Close()

	ctx := context.Background()

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(b, err)
	defer tx.Rollback(ctx)

	// Create test account
	testEmail := fmt.Sprintf("bench_%d@test.com", time.Now().UnixNano())
	req := CreateAccountRequest{
		Email:     testEmail,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	_, err = db.CreateAccount(ctx, tx, req)
	require.NoError(b, err)

	require.NoError(b, tx.Commit(ctx))

	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(b, err)

	// Reopen transaction for mailbox operations and inserts
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(b, err)
	defer tx.Rollback(ctx)

	// Create a mailbox
	err = db.CreateMailbox(ctx, tx, accountID, "BenchBox", nil)
	require.NoError(b, err)

	require.NoError(b, tx.Commit(ctx))

	mbox, err := db.GetMailboxByName(ctx, accountID, "BenchBox")
	require.NoError(b, err)

	// Reopen transaction for bulk insert
	tx, err = db.GetWritePool().Begin(ctx)
	require.NoError(b, err)
	defer tx.Rollback(ctx)

	b.Logf("Generating 100,000 messages for benchmarking...")

	// Fast bulk insert using PostgreSQL generate_series
	_, err = tx.Exec(ctx, `
		INSERT INTO messages (
			account_id, mailbox_id, mailbox_path, uid, content_hash, s3_domain, s3_localpart,
			size, internal_date, uploaded, created_modseq, subject_sort, 
			from_name_sort, from_email_sort, to_name_sort, to_email_sort, cc_email_sort, recipients_json, message_id, sent_date, subject, body_structure, in_reply_to
		)
		SELECT 
			$1::bigint, $2::bigint, '', seq, 'hash' || seq, 'test.com', 'bench' || seq,
			1024, now(), true, seq, '', '', '', '', '', '', '[]'::jsonb, '<msg' || seq || '@bench>', now(), 'Subject ' || seq, '', ''
		FROM generate_series(1, 100000) AS seq
	`, accountID, mbox.ID)
	require.NoError(b, err)

	_, err = tx.Exec(ctx, `
		INSERT INTO message_state (
			message_id, mailbox_id, flags, custom_flags, updated_modseq, flags_changed_at
		)
		SELECT 
			id, $1::bigint, 0, '[]'::jsonb, 1, now()
		FROM messages 
		WHERE mailbox_id = $1::bigint
	`, mbox.ID)
	require.NoError(b, err)

	require.NoError(b, tx.Commit(ctx))

	// Prepare a fetch list of 1000 messages sparsely distributed across the mailbox
	// This simulates a FETCH 1:1000 or sparse SEARCH results.
	var messages []Message
	for i := 1; i <= 1000; i++ {
		uid := i * 100 // 100, 200, 300, ..., 100,000
		messages = append(messages, Message{
			ID:  int64(uid),
			UID: imap.UID(uid),
		})
	}

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		err := db.HydrateMessageSequences(ctx, mbox.ID, messages)
		if err != nil {
			b.Fatalf("hydrate failed: %v", err)
		}
	}
}
