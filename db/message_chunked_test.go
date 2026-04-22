package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/require"
)

// TestChunkedMessageFetch tests chunked fetching with a large mailbox
func TestChunkedMessageFetch(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()

	// Override chunk size to test chunking with fewer messages
	originalChunkSize := db.fetchChunkSize
	db.fetchChunkSize = 100 // Small chunk size for testing
	defer func() { db.fetchChunkSize = originalChunkSize }()

	// Create test account directly via SQL
	var accountID int64
	err := db.GetWritePool().QueryRow(ctx, `
		INSERT INTO accounts DEFAULT VALUES RETURNING id
	`).Scan(&accountID)
	require.NoError(t, err, "Failed to create test account")

	// Create mailbox directly via SQL
	var mailboxID int64
	err = db.GetWritePool().QueryRow(ctx, `
		INSERT INTO mailboxes (account_id, name, subscribed, uid_validity, highest_uid)
		VALUES ($1, $2, true, 1, 0)
		RETURNING id
	`, accountID, "INBOX").Scan(&mailboxID)
	require.NoError(t, err, "Failed to create test mailbox")

	// Insert 1000 test messages (will require 10 chunks at size 100)
	const messageCount = 1000
	t.Logf("Inserting %d test messages...", messageCount)

	for i := 0; i < messageCount; i++ {
		_, err := db.GetWritePool().Exec(ctx, `
			INSERT INTO messages (
				account_id, mailbox_id, uid, content_hash, s3_domain, s3_localpart,
				uploaded, size, internal_date, subject, sent_date, created_modseq,
				recipients_json, message_id, body_structure, in_reply_to
			) VALUES ($1, $2, $3, $4, $5, $6, true, 1024, $7, $8, $7, nextval('messages_modseq'),
				'[]'::jsonb, $9, ''::bytea, '')
		`, accountID, mailboxID, i+1, fmt.Sprintf("hash-%d", i),
			"test.com", fmt.Sprintf("user-%d", i), time.Now(),
			fmt.Sprintf("Test Message %d", i),
			fmt.Sprintf("<msg-%d@test.com>", i))
		require.NoError(t, err, "Failed to insert message %d", i)
	}

	t.Logf("Successfully inserted %d messages", messageCount)

	// Test 1: Fetch all messages via UID range (should trigger chunking)
	t.Run("fetch_all_via_uid_range", func(t *testing.T) {
		uidSet := imap.UIDSet{imap.UIDRange{Start: 1, Stop: imap.UID(messageCount)}}

		start := time.Now()
		messages, err := db.GetMessagesByNumSet(ctx, mailboxID, uidSet)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("Failed to fetch messages: %v", err)
		}

		if len(messages) != messageCount {
			t.Errorf("Expected %d messages, got %d", messageCount, len(messages))
		}

		t.Logf("Fetched %d messages in %v (should have used chunking)", len(messages), elapsed)
	})

	// Test 2: Fetch all messages via open-ended UID range (1:*)
	t.Run("fetch_all_via_uid_star", func(t *testing.T) {
		uidSet := imap.UIDSet{imap.UIDRange{Start: 1, Stop: 0}} // 0 means open-ended

		start := time.Now()
		messages, err := db.GetMessagesByNumSet(ctx, mailboxID, uidSet)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("Failed to fetch messages: %v", err)
		}

		if len(messages) != messageCount {
			t.Errorf("Expected %d messages, got %d", messageCount, len(messages))
		}

		t.Logf("Fetched %d messages via UID 1:* in %v (should have used chunking)", len(messages), elapsed)
	})

	// Test 3: Fetch all messages via SeqSet (1:*)
	t.Run("fetch_all_via_seq_star", func(t *testing.T) {
		seqSet := imap.SeqSet{imap.SeqRange{Start: 1, Stop: 0}} // 0 means open-ended

		start := time.Now()
		messages, err := db.GetMessagesByNumSet(ctx, mailboxID, seqSet)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("Failed to fetch messages: %v", err)
		}

		if len(messages) != messageCount {
			t.Errorf("Expected %d messages, got %d", messageCount, len(messages))
		}

		t.Logf("Fetched %d messages via Seq 1:* in %v (should have used chunking)", len(messages), elapsed)
	})

	// Test 5: Verify message ordering is preserved through chunking
	t.Run("message_ordering", func(t *testing.T) {
		uidSet := imap.UIDSet{imap.UIDRange{Start: 1, Stop: imap.UID(messageCount)}}

		messages, err := db.GetMessagesByNumSet(ctx, mailboxID, uidSet)
		if err != nil {
			t.Fatalf("Failed to fetch messages: %v", err)
		}

		// Verify UIDs are in ascending order
		for i := 0; i < len(messages)-1; i++ {
			if messages[i].UID >= messages[i+1].UID {
				t.Errorf("Messages not in order: UID[%d]=%d >= UID[%d]=%d",
					i, messages[i].UID, i+1, messages[i+1].UID)
			}
		}

		t.Log("Message ordering preserved through chunking")
	})

	// Test 6: Context cancellation during chunking
	t.Run("context_cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		time.Sleep(10 * time.Millisecond) // Ensure context expires

		uidSet := imap.UIDSet{imap.UIDRange{Start: 1, Stop: imap.UID(messageCount)}}

		_, err := db.GetMessagesByNumSet(ctx, mailboxID, uidSet)
		if err == nil {
			t.Fatal("Expected error from cancelled context, got nil")
		}

		t.Logf("Correctly handled context cancellation: %v", err)
	})
}

// TestChunkedMessageFetchLargeMailbox tests with an even larger mailbox
func TestChunkedMessageFetchLargeMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large mailbox integration test in short mode")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()

	// Use realistic chunk size
	db.fetchChunkSize = 5000

	// Create test account directly via SQL
	var accountID int64
	err := db.GetWritePool().QueryRow(ctx, `
		INSERT INTO accounts DEFAULT VALUES RETURNING id
	`).Scan(&accountID)
	require.NoError(t, err, "Failed to create test account")

	// Create mailbox directly via SQL
	var mailboxID int64
	err = db.GetWritePool().QueryRow(ctx, `
		INSERT INTO mailboxes (account_id, name, subscribed, uid_validity, highest_uid)
		VALUES ($1, $2, true, 1, 0)
		RETURNING id
	`, accountID, "INBOX").Scan(&mailboxID)
	require.NoError(t, err, "Failed to create test mailbox")

	// Insert 10,000 test messages (will require 2 chunks at size 5000)
	const messageCount = 10000
	t.Logf("Inserting %d test messages (this may take a minute)...", messageCount)

	start := time.Now()
	for i := 0; i < messageCount; i++ {
		_, err := db.GetWritePool().Exec(ctx, `
			INSERT INTO messages (
				account_id, mailbox_id, uid, content_hash, s3_domain, s3_localpart,
				uploaded, size, internal_date, subject, sent_date, created_modseq,
				recipients_json, message_id, body_structure, in_reply_to
			) VALUES ($1, $2, $3, $4, $5, $6, true, 1024, $7, $8, $7, nextval('messages_modseq'),
				'[]'::jsonb, $9, ''::bytea, '')
		`, accountID, mailboxID, i+1, fmt.Sprintf("hash-%d", i),
			"test.com", fmt.Sprintf("user-%d", i), time.Now(),
			fmt.Sprintf("Test Message %d", i),
			fmt.Sprintf("<msg-%d@test.com>", i))
		require.NoError(t, err, "Failed to insert message %d", i)

		if (i+1)%1000 == 0 {
			t.Logf("Inserted %d/%d messages...", i+1, messageCount)
		}
	}
	insertTime := time.Since(start)
	t.Logf("Successfully inserted %d messages in %v", messageCount, insertTime)

	// Fetch all messages
	t.Run("fetch_10k_messages", func(t *testing.T) {
		uidSet := imap.UIDSet{imap.UIDRange{Start: 1, Stop: imap.UID(messageCount)}}

		start := time.Now()
		messages, err := db.GetMessagesByNumSet(ctx, mailboxID, uidSet)
		elapsed := time.Since(start)

		if err != nil {
			t.Fatalf("Failed to fetch messages: %v", err)
		}

		if len(messages) != messageCount {
			t.Errorf("Expected %d messages, got %d", messageCount, len(messages))
		}

		t.Logf("Fetched %d messages in %v (avg: %v per message)",
			len(messages), elapsed, elapsed/time.Duration(len(messages)))
	})
}
