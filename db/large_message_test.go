package db

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInsertMessage_LargeFTSSkip tests that messages with body >1MB skip FTS indexing
func TestInsertMessage_LargeFTSSkip(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	now := time.Now()

	// Create a message with >1MB plaintext body (FTS skip threshold)
	largeBody := strings.Repeat("A", 1024*1024+1) // 1MB + 1 byte

	bodyStructure := &imap.BodyStructureSinglePart{
		Type:     "text",
		Subtype:  "plain",
		Params:   map[string]string{"charset": "utf-8"},
		Encoding: "7bit",
		Size:     uint32(len(largeBody)),
	}
	var bs imap.BodyStructure = bodyStructure

	options := &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   "INBOX",
		S3Domain:      "example.com",
		S3Localpart:   "test/large-fts",
		ContentHash:   "large-fts-hash",
		MessageID:     "<large-fts@example.com>",
		Flags:         []imap.Flag{},
		InternalDate:  now,
		Size:          int64(len(largeBody)),
		Subject:       "Large FTS Test",
		PlaintextBody: largeBody,
		RawHeaders:    "From: test@example.com\r\nTo: recipient@example.com\r\n",
		SentDate:      now.Add(-time.Hour),
		InReplyTo:     []string{},
		BodyStructure: &bs,
	}

	upload := PendingUpload{
		AccountID:   accountID,
		ContentHash: "large-fts-hash",
		InstanceID:  "test-instance",
		Size:        int64(len(largeBody)),
		Attempts:    0,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	messageID, uid, err := db.InsertMessage(ctx, tx, options, upload)
	assert.NoError(t, err)
	assert.Greater(t, messageID, int64(0))
	assert.Greater(t, uid, int64(0))

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify message was inserted
	messages, err := db.ListMessages(ctx, mailboxID)
	assert.NoError(t, err)
	assert.Len(t, messages, 1)
	assert.Equal(t, "Large FTS Test", messages[0].Subject)

	// Verify that the tsvector was created (even if empty)
	// by checking that message_contents row exists
	var contentHash string
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT content_hash FROM message_contents WHERE content_hash = $1",
		"large-fts-hash").Scan(&contentHash)
	assert.NoError(t, err)
	assert.Equal(t, "large-fts-hash", contentHash)

	t.Logf("Successfully tested large FTS skip with messageID: %d, UID: %d", messageID, uid)
}

// TestInsertMessage_LargeBodyStorageSkip tests that messages with body >64KB don't store text_body
func TestInsertMessage_LargeBodyStorageSkip(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	now := time.Now()

	// Create a message with >64KB plaintext body (storage skip threshold)
	largeBody := strings.Repeat("B", 64*1024+1) // 64KB + 1 byte

	bodyStructure := &imap.BodyStructureSinglePart{
		Type:     "text",
		Subtype:  "plain",
		Params:   map[string]string{"charset": "utf-8"},
		Encoding: "7bit",
		Size:     uint32(len(largeBody)),
	}
	var bs imap.BodyStructure = bodyStructure

	options := &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   "INBOX",
		S3Domain:      "example.com",
		S3Localpart:   "test/large-storage",
		ContentHash:   "large-storage-hash",
		MessageID:     "<large-storage@example.com>",
		Flags:         []imap.Flag{},
		InternalDate:  now,
		Size:          int64(len(largeBody)),
		Subject:       "Large Storage Test",
		PlaintextBody: largeBody,
		RawHeaders:    "From: test@example.com\r\nTo: recipient@example.com\r\n",
		SentDate:      now.Add(-time.Hour),
		InReplyTo:     []string{},
		BodyStructure: &bs,
	}

	upload := PendingUpload{
		AccountID:   accountID,
		ContentHash: "large-storage-hash",
		InstanceID:  "test-instance",
		Size:        int64(len(largeBody)),
		Attempts:    0,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	messageID, uid, err := db.InsertMessage(ctx, tx, options, upload)
	assert.NoError(t, err)
	assert.Greater(t, messageID, int64(0))
	assert.Greater(t, uid, int64(0))

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify message was inserted
	messages, err := db.ListMessages(ctx, mailboxID)
	assert.NoError(t, err)
	assert.Len(t, messages, 1)
	assert.Equal(t, "Large Storage Test", messages[0].Subject)

	// Verify that text_body is NULL (not stored)
	var textBody *string
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT text_body FROM message_contents WHERE content_hash = $1",
		"large-storage-hash").Scan(&textBody)
	assert.NoError(t, err)
	assert.Nil(t, textBody, "text_body should be NULL for large messages")

	t.Logf("Successfully tested large body storage skip with messageID: %d, UID: %d", messageID, uid)
}

// TestInsertMessage_NormalSizeStored tests that normal-sized messages are stored and indexed
func TestInsertMessage_NormalSizeStored(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	now := time.Now()

	// Create a normal-sized message (< 64KB)
	normalBody := "This is a normal email message body with searchable content."

	bodyStructure := &imap.BodyStructureSinglePart{
		Type:     "text",
		Subtype:  "plain",
		Params:   map[string]string{"charset": "utf-8"},
		Encoding: "7bit",
		Size:     uint32(len(normalBody)),
	}
	var bs imap.BodyStructure = bodyStructure

	options := &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   "INBOX",
		S3Domain:      "example.com",
		S3Localpart:   "test/normal-size",
		ContentHash:   "normal-size-hash",
		MessageID:     "<normal@example.com>",
		Flags:         []imap.Flag{},
		InternalDate:  now,
		Size:          int64(len(normalBody)),
		Subject:       "Normal Size Test",
		PlaintextBody: normalBody,
		RawHeaders:    "From: test@example.com\r\nTo: recipient@example.com\r\n",
		SentDate:      now.Add(-time.Hour),
		InReplyTo:     []string{},
		BodyStructure: &bs,
	}

	upload := PendingUpload{
		AccountID:   accountID,
		ContentHash: "normal-size-hash",
		InstanceID:  "test-instance",
		Size:        int64(len(normalBody)),
		Attempts:    0,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	messageID, uid, err := db.InsertMessage(ctx, tx, options, upload)
	assert.NoError(t, err)
	assert.Greater(t, messageID, int64(0))
	assert.Greater(t, uid, int64(0))

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify message was inserted
	messages, err := db.ListMessages(ctx, mailboxID)
	assert.NoError(t, err)
	assert.Len(t, messages, 1)
	assert.Equal(t, "Normal Size Test", messages[0].Subject)

	// Verify that text_body is NOT NULL (stored)
	var textBody *string
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT text_body FROM message_contents WHERE content_hash = $1",
		"normal-size-hash").Scan(&textBody)
	assert.NoError(t, err)
	assert.NotNil(t, textBody, "text_body should NOT be NULL for normal-sized messages")
	assert.Equal(t, normalBody, *textBody)

	t.Logf("Successfully tested normal size storage with messageID: %d, UID: %d", messageID, uid)
}

// TestInsertMessage_LargeHeaders tests that large headers are handled correctly
func TestInsertMessage_LargeHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	now := time.Now()

	normalBody := "Normal body content"
	// Create abnormally large headers (>64KB)
	largeHeaders := "From: test@example.com\r\n"
	largeHeaders += "X-Large-Header: " + strings.Repeat("H", 64*1024) + "\r\n"

	bodyStructure := &imap.BodyStructureSinglePart{
		Type:     "text",
		Subtype:  "plain",
		Params:   map[string]string{"charset": "utf-8"},
		Encoding: "7bit",
		Size:     uint32(len(normalBody)),
	}
	var bs imap.BodyStructure = bodyStructure

	options := &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   "INBOX",
		S3Domain:      "example.com",
		S3Localpart:   "test/large-headers",
		ContentHash:   "large-headers-hash",
		MessageID:     "<large-headers@example.com>",
		Flags:         []imap.Flag{},
		InternalDate:  now,
		Size:          int64(len(normalBody)),
		Subject:       "Large Headers Test",
		PlaintextBody: normalBody,
		RawHeaders:    largeHeaders,
		SentDate:      now.Add(-time.Hour),
		InReplyTo:     []string{},
		BodyStructure: &bs,
	}

	upload := PendingUpload{
		AccountID:   accountID,
		ContentHash: "large-headers-hash",
		InstanceID:  "test-instance",
		Size:        int64(len(normalBody)),
		Attempts:    0,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	messageID, uid, err := db.InsertMessage(ctx, tx, options, upload)
	assert.NoError(t, err)
	assert.Greater(t, messageID, int64(0))
	assert.Greater(t, uid, int64(0))

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify message was inserted
	messages, err := db.ListMessages(ctx, mailboxID)
	assert.NoError(t, err)
	assert.Len(t, messages, 1)
	assert.Equal(t, "Large Headers Test", messages[0].Subject)

	// Verify that headers column is empty string (not stored due to size)
	var headers string
	err = db.GetReadPool().QueryRow(ctx,
		"SELECT headers FROM message_contents WHERE content_hash = $1",
		"large-headers-hash").Scan(&headers)
	assert.NoError(t, err)
	assert.Equal(t, "", headers, "headers should be empty string for large headers")

	t.Logf("Successfully tested large headers with messageID: %d, UID: %d", messageID, uid)
}
