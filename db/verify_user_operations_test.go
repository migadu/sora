package db

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetMessagesByContentHash_NullSubject verifies that GetMessagesByContentHash
// coalesces NULL subjects instead of failing to scan into string.
func TestGetMessagesByContentHash_NullSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	ctx := context.Background()

	nonce := time.Now().UnixNano()
	email := fmt.Sprintf("null_subj_%d@example.com", nonce)

	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	accountID, err := database.CreateAccount(ctx, tx, CreateAccountRequest{
		Email:     email,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, database.CreateMailbox(ctx, tx, accountID, "INBOX", nil))
	require.NoError(t, tx.Commit(ctx))

	t.Cleanup(func() {
		_, _ = database.GetWritePool().Exec(ctx, "DELETE FROM messages WHERE account_id = $1", accountID)
		_, _ = database.GetWritePool().Exec(ctx, "DELETE FROM mailboxes WHERE account_id = $1", accountID)
		_, _ = database.GetWritePool().Exec(ctx, "DELETE FROM credentials WHERE account_id = $1", accountID)
		_, _ = database.GetWritePool().Exec(ctx, "DELETE FROM accounts WHERE id = $1", accountID)
	})

	mailbox, err := database.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)

	contentHash := fmt.Sprintf("%064x", nonce)
	_, err = database.GetWritePool().Exec(ctx, `
		INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, subject, expunged_at, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq)
		VALUES ($1, $2, 1, $3, now(), now(), 128, NULL, NULL, TRUE, 'example.com', $4, $5, 'body', '[]', nextval('messages_modseq'))
	`, accountID, mailbox.ID, contentHash, fmt.Sprintf("null_subj_%d", nonce), fmt.Sprintf("<null-subj-%d@example.com>", nonce))
	require.NoError(t, err)

	msgs, err := database.GetMessagesByContentHash(ctx, accountID, contentHash)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.Equal(t, "", msgs[0].Subject)
}

// TestMarkMessagesAsNotUploaded_SlashLocalpartAndPendingUpload verifies that
// MarkMessagesAsNotUploaded splits S3 keys around the first and last '/' so
// localparts containing '/' are matched accurately without clobbering unrelated
// prefixes, and leaves rows protected by an active pending_uploads entry intact.
func TestMarkMessagesAsNotUploaded_SlashLocalpartAndPendingUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	ctx := context.Background()

	nonce := time.Now().UnixNano()
	email := fmt.Sprintf("mark_slash_%d@example.com", nonce)

	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	accountID, err := database.CreateAccount(ctx, tx, CreateAccountRequest{
		Email:     email,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, database.CreateMailbox(ctx, tx, accountID, "INBOX", nil))
	require.NoError(t, tx.Commit(ctx))

	t.Cleanup(func() {
		_, _ = database.GetWritePool().Exec(ctx, "DELETE FROM pending_uploads WHERE account_id = $1", accountID)
		_, _ = database.GetWritePool().Exec(ctx, "DELETE FROM messages WHERE account_id = $1", accountID)
		_, _ = database.GetWritePool().Exec(ctx, "DELETE FROM mailboxes WHERE account_id = $1", accountID)
		_, _ = database.GetWritePool().Exec(ctx, "DELETE FROM credentials WHERE account_id = $1", accountID)
		_, _ = database.GetWritePool().Exec(ctx, "DELETE FROM accounts WHERE id = $1", accountID)
	})

	mailbox, err := database.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)

	insertMsg := func(uid int, localpart, hash string) int64 {
		var id int64
		err := database.GetWritePool().QueryRow(ctx, `
			INSERT INTO messages (account_id, mailbox_id, uid, content_hash, sent_date, internal_date, size, expunged_at, uploaded, s3_domain, s3_localpart, message_id, body_structure, recipients_json, created_modseq)
			VALUES ($1, $2, $3, $4, now(), now(), 256, NULL, TRUE, 'example.com', $5, $6, 'body', '[]', nextval('messages_modseq'))
			RETURNING id
		`, accountID, mailbox.ID, uid, hash, localpart, fmt.Sprintf("<msg-%d-%d@example.com>", uid, nonce)).Scan(&id)
		require.NoError(t, err)
		return id
	}

	isUploaded := func(id int64) bool {
		var uploaded bool
		err := database.GetWritePool().QueryRow(ctx, "SELECT uploaded FROM messages WHERE id = $1", id).Scan(&uploaded)
		require.NoError(t, err)
		return uploaded
	}

	t.Run("slash_in_localpart_and_isolation", func(t *testing.T) {
		hashSlash := strings.Repeat("a", 48) + fmt.Sprintf("%016x", nonce)
		hashVictim := strings.Repeat("b", 48) + fmt.Sprintf("%016x", nonce)
		hashCollider := strings.Repeat("c", 48) + fmt.Sprintf("%016x", nonce)

		userPrefix := fmt.Sprintf("user_%d", nonce)
		slashLocal := fmt.Sprintf("first/last_%d", nonce)
		colliderLocal := userPrefix + "/" + hashVictim

		slashID := insertMsg(1, slashLocal, hashSlash)
		victimID := insertMsg(2, userPrefix, hashVictim)
		colliderID := insertMsg(3, colliderLocal, hashCollider)

		rowsAffected, err := database.MarkMessagesAsNotUploaded(ctx, []string{
			"example.com/" + slashLocal + "/" + hashSlash,
			"example.com/" + colliderLocal + "/" + hashCollider,
		})
		require.NoError(t, err)
		assert.Equal(t, int64(2), rowsAffected, "both slash-localpart messages must be updated")
		assert.False(t, isUploaded(slashID), "first/last@example.com message must be marked not uploaded")
		assert.False(t, isUploaded(colliderID), "user/<64hex>@example.com message must be marked not uploaded")
		assert.True(t, isUploaded(victimID), "unrelated user@example.com message with matching 64hex must remain uploaded")
	})

	t.Run("pending_upload_guard", func(t *testing.T) {
		hashPending := strings.Repeat("d", 48) + fmt.Sprintf("%016x", nonce)
		localpart := fmt.Sprintf("pending_guard_%d", nonce)
		msgID := insertMsg(10, localpart, hashPending)

		_, err := database.GetWritePool().Exec(ctx, `
			INSERT INTO pending_uploads (instance_id, content_hash, size, account_id)
			VALUES ('verify-guard-test', $1, 256, $2)
		`, hashPending, accountID)
		require.NoError(t, err)

		rowsAffected, err := database.MarkMessagesAsNotUploaded(ctx, []string{
			"example.com/" + localpart + "/" + hashPending,
		})
		require.NoError(t, err)
		assert.Equal(t, int64(0), rowsAffected, "message with an active pending_uploads row must not be marked not uploaded")
		assert.True(t, isUploaded(msgID), "uploaded flag must remain TRUE while pending_uploads exists")
	})
}
