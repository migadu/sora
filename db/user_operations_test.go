package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetAllMessagesForUserVerification tests the GetAllMessagesForUserVerification method
func TestGetAllMessagesForUserVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()

	// Create a test account
	testEmail := fmt.Sprintf("verify_test_%d@example.com", time.Now().UnixNano())

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	req := CreateAccountRequest{
		Email:     testEmail,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get account ID
	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	// Create INBOX mailbox
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx2, accountID, "INBOX", nil)
	require.NoError(t, err)
	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Get mailbox
	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)

	// Test 1: Empty mailbox returns empty slice
	t.Run("empty mailbox", func(t *testing.T) {
		messages, err := db.GetAllMessagesForUserVerification(ctx, accountID)
		require.NoError(t, err)
		assert.Empty(t, messages)
	})

	// Create test messages using raw SQL (following cleaner_test.go pattern)
	testMessages := []struct {
		contentHash string
		s3Domain    string
		s3Localpart string
		expunged    bool
	}{
		{"hash001", "example.com", "user1", false},
		{"hash002", "example.com", "user1", false},
		{"hash003", "example.com", "user1", false},
		{"hash004", "example.com", "user1", true}, // This one is expunged
	}

	for i, tm := range testMessages {
		tx3, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)

		expungedAt := "NULL"
		if tm.expunged {
			expungedAt = "NOW()"
		}

		query := fmt.Sprintf(`
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, flags, expunged_at, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq)
			VALUES ($1, $2, $3, $4, $5, $5, $6, 0, %s, TRUE, $7, $8, $9, 'body', '[]', $10)
		`, expungedAt)

		_, err = tx3.Exec(ctx, query,
			accountID,
			mailbox.ID,
			i+1,                       // UID
			tm.contentHash,            // content_hash
			time.Now(),                // sent_date/internal_date
			1024+i,                    // size
			tm.s3Domain,               // s3_domain
			tm.s3Localpart,            // s3_localpart
			fmt.Sprintf("msg%d", i+1), // message_id
			int64(i+1),                // created_modseq
		)
		require.NoError(t, err)
		require.NoError(t, tx3.Commit(ctx))
	}

	// Test 2: Returns all non-expunged messages
	t.Run("returns non-expunged messages", func(t *testing.T) {
		messages, err := db.GetAllMessagesForUserVerification(ctx, accountID)
		require.NoError(t, err)

		// Should return 3 messages (4th is expunged)
		assert.Len(t, messages, 3)
	})

	// Test 3: Verify S3 key construction
	t.Run("constructs S3 keys correctly", func(t *testing.T) {
		messages, err := db.GetAllMessagesForUserVerification(ctx, accountID)
		require.NoError(t, err)

		for i, msg := range messages {
			expectedKey := fmt.Sprintf("%s/%s/%s", testMessages[i].s3Domain, testMessages[i].s3Localpart, testMessages[i].contentHash)
			assert.Equal(t, expectedKey, msg.S3Key, "S3 key mismatch for message %d", i)
			assert.Equal(t, testMessages[i].contentHash, msg.ContentHash)
			assert.Equal(t, testMessages[i].s3Domain, msg.S3Domain)
			assert.Equal(t, testMessages[i].s3Localpart, msg.S3Localpart)
		}
	})

	// Test 4: All messages have valid IDs
	t.Run("messages have valid IDs", func(t *testing.T) {
		messages, err := db.GetAllMessagesForUserVerification(ctx, accountID)
		require.NoError(t, err)

		for _, msg := range messages {
			assert.NotZero(t, msg.ID)
			assert.NotEmpty(t, msg.ContentHash)
			assert.NotEmpty(t, msg.S3Domain)
			assert.NotEmpty(t, msg.S3Localpart)
			assert.NotEmpty(t, msg.S3Key)
		}
	})

	// Test 5: Different user doesn't see messages
	t.Run("different user returns empty", func(t *testing.T) {
		otherEmail := fmt.Sprintf("other_user_%d@example.com", time.Now().UnixNano())
		tx4, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)

		req2 := CreateAccountRequest{
			Email:     otherEmail,
			Password:  "password123",
			IsPrimary: true,
			HashType:  "bcrypt",
		}
		err = db.CreateAccount(ctx, tx4, req2)
		require.NoError(t, err)
		require.NoError(t, tx4.Commit(ctx))

		otherAccountID, err := db.GetAccountIDByAddress(ctx, otherEmail)
		require.NoError(t, err)

		messages, err := db.GetAllMessagesForUserVerification(ctx, otherAccountID)
		require.NoError(t, err)
		assert.Empty(t, messages)
	})

	// Test 6: Order is consistent (by ID)
	t.Run("returns messages in ID order", func(t *testing.T) {
		messages, err := db.GetAllMessagesForUserVerification(ctx, accountID)
		require.NoError(t, err)

		// Should be in ascending ID order
		for i := 1; i < len(messages); i++ {
			assert.Less(t, messages[i-1].ID, messages[i].ID, "Messages should be ordered by ID")
		}
	})

	// Cleanup
	_, err = db.GetWritePool().Exec(ctx, "DELETE FROM messages WHERE account_id = $1", accountID)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, "DELETE FROM mailboxes WHERE account_id = $1", accountID)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, "DELETE FROM credentials WHERE account_id = $1", accountID)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, "DELETE FROM accounts WHERE id = $1", accountID)
	require.NoError(t, err)
}

// TestMessageS3Info_Structure tests the MessageS3Info struct
func TestMessageS3Info_Structure(t *testing.T) {
	msg := MessageS3Info{
		ID:          123,
		ContentHash: "abc123hash",
		S3Domain:    "example.com",
		S3Localpart: "user1",
		S3Key:       "example.com/user1/abc123hash",
	}

	assert.Equal(t, int64(123), msg.ID)
	assert.Equal(t, "abc123hash", msg.ContentHash)
	assert.Equal(t, "example.com", msg.S3Domain)
	assert.Equal(t, "user1", msg.S3Localpart)
	assert.Equal(t, "example.com/user1/abc123hash", msg.S3Key)
}

// TestMarkMessagesAsNotUploaded tests marking messages as not uploaded
func TestMarkMessagesAsNotUploaded(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()

	// Create test account
	testEmail := fmt.Sprintf("mark_test_%d@example.com", time.Now().UnixNano())

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	req := CreateAccountRequest{
		Email:     testEmail,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	}
	err = db.CreateAccount(ctx, tx, req)
	require.NoError(t, err)
	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Get account ID
	accountID, err := db.GetAccountIDByAddress(ctx, testEmail)
	require.NoError(t, err)

	// Create mailbox
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx2, accountID, "INBOX", nil)
	require.NoError(t, err)
	err = tx2.Commit(ctx)
	require.NoError(t, err)

	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)

	// Create 3 messages, all uploaded
	testMessages := []struct {
		hash      string
		domain    string
		localpart string
	}{
		{"hash001", "example.com", "user1"},
		{"hash002", "example.com", "user1"},
		{"hash003", "example.com", "user1"},
	}

	for i, tm := range testMessages {
		tx3, err := db.GetWritePool().Begin(ctx)
		require.NoError(t, err)

		query := `
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, flags, expunged_at, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq)
			VALUES ($1, $2, $3, $4, $5, $5, $6, 0, NULL, TRUE, $7, $8, $9, 'body', '[]', $10)
		`

		_, err = tx3.Exec(ctx, query,
			accountID,
			mailbox.ID,
			i+1,
			tm.hash,
			time.Now(),
			1024+i,
			tm.domain,
			tm.localpart,
			fmt.Sprintf("msg%d", i+1),
			int64(i+1),
		)
		require.NoError(t, err)
		require.NoError(t, tx3.Commit(ctx))
	}

	// Verify all messages are uploaded
	var uploadedCount int
	err = db.GetReadPool().QueryRow(ctx, "SELECT COUNT(*) FROM messages WHERE account_id = $1 AND uploaded = TRUE", accountID).Scan(&uploadedCount)
	require.NoError(t, err)
	assert.Equal(t, 3, uploadedCount, "All messages should be uploaded initially")

	// Test 1: Mark messages as not uploaded using S3 keys
	t.Run("mark messages as not uploaded", func(t *testing.T) {
		s3Keys := []string{
			"example.com/user1/hash001",
			"example.com/user1/hash002",
		}

		rowsAffected, err := db.MarkMessagesAsNotUploaded(ctx, s3Keys)
		require.NoError(t, err)
		assert.Equal(t, int64(2), rowsAffected, "Should mark 2 messages")

		// Verify messages are marked as not uploaded
		var notUploadedCount int
		err = db.GetReadPool().QueryRow(ctx, "SELECT COUNT(*) FROM messages WHERE account_id = $1 AND uploaded = FALSE", accountID).Scan(&notUploadedCount)
		require.NoError(t, err)
		assert.Equal(t, 2, notUploadedCount, "2 messages should be not uploaded")

		// Verify one message is still uploaded
		err = db.GetReadPool().QueryRow(ctx, "SELECT COUNT(*) FROM messages WHERE account_id = $1 AND uploaded = TRUE", accountID).Scan(&uploadedCount)
		require.NoError(t, err)
		assert.Equal(t, 1, uploadedCount, "1 message should still be uploaded")
	})

	// Test 2: Empty array returns 0
	t.Run("empty array", func(t *testing.T) {
		rowsAffected, err := db.MarkMessagesAsNotUploaded(ctx, []string{})
		require.NoError(t, err)
		assert.Equal(t, int64(0), rowsAffected)
	})

	// Test 3: Non-existent keys don't affect anything
	t.Run("non-existent keys", func(t *testing.T) {
		s3Keys := []string{
			"example.com/user1/nonexistent",
		}

		rowsAffected, err := db.MarkMessagesAsNotUploaded(ctx, s3Keys)
		require.NoError(t, err)
		assert.Equal(t, int64(0), rowsAffected, "Should not mark any messages")
	})

	// Cleanup
	_, err = db.GetWritePool().Exec(ctx, "DELETE FROM messages WHERE account_id = $1", accountID)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, "DELETE FROM mailboxes WHERE account_id = $1", accountID)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, "DELETE FROM credentials WHERE account_id = $1", accountID)
	require.NoError(t, err)
	_, err = db.GetWritePool().Exec(ctx, "DELETE FROM accounts WHERE id = $1", accountID)
	require.NoError(t, err)
}
