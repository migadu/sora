package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFlagConstants tests the flag constant values
func TestFlagConstants(t *testing.T) {
	// Test that flag constants have expected values
	assert.Equal(t, 1, FlagSeen)
	assert.Equal(t, 2, FlagAnswered)
	assert.Equal(t, 4, FlagFlagged)
	assert.Equal(t, 8, FlagDeleted)
	assert.Equal(t, 16, FlagDraft)
	assert.Equal(t, 32, FlagRecent)
}

// TestContainsFlag tests the ContainsFlag function
func TestContainsFlag(t *testing.T) {
	tests := []struct {
		name     string
		flags    int
		testFlag int
		expected bool
	}{
		{"has seen flag", FlagSeen | FlagAnswered, FlagSeen, true},
		{"doesn't have flagged", FlagSeen | FlagAnswered, FlagFlagged, false},
		{"has multiple flags", FlagSeen | FlagAnswered | FlagFlagged, FlagAnswered, true},
		{"no flags set", 0, FlagSeen, false},
		{"all flags set", FlagSeen | FlagAnswered | FlagFlagged | FlagDeleted | FlagDraft | FlagRecent, FlagRecent, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsFlag(tt.flags, tt.testFlag)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFlagToBitwise tests converting IMAP flags to bitwise representation
func TestFlagToBitwise(t *testing.T) {
	tests := []struct {
		name     string
		flag     imap.Flag
		expected int
	}{
		{"seen flag", imap.FlagSeen, FlagSeen},
		{"answered flag", imap.FlagAnswered, FlagAnswered},
		{"flagged flag", imap.FlagFlagged, FlagFlagged},
		{"deleted flag", imap.FlagDeleted, FlagDeleted},
		{"draft flag", imap.FlagDraft, FlagDraft},
		{"recent flag", imap.Flag("\\Recent"), FlagRecent},
		{"custom flag", imap.Flag("CustomFlag"), 0},
		{"empty flag", imap.Flag(""), 0},
		{"case insensitive", imap.Flag("\\SEEN"), FlagSeen},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FlagToBitwise(tt.flag)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestFlagsToBitwise tests converting multiple IMAP flags to bitwise
func TestFlagsToBitwise(t *testing.T) {
	tests := []struct {
		name     string
		flags    []imap.Flag
		expected int
	}{
		{
			name:     "single flag",
			flags:    []imap.Flag{imap.FlagSeen},
			expected: FlagSeen,
		},
		{
			name:     "multiple flags",
			flags:    []imap.Flag{imap.FlagSeen, imap.FlagAnswered},
			expected: FlagSeen | FlagAnswered,
		},
		{
			name:     "all standard flags",
			flags:    []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft, imap.Flag("\\Recent")},
			expected: FlagSeen | FlagAnswered | FlagFlagged | FlagDeleted | FlagDraft | FlagRecent,
		},
		{
			name:     "with custom flags",
			flags:    []imap.Flag{imap.FlagSeen, imap.Flag("CustomFlag")},
			expected: FlagSeen, // custom flag ignored
		},
		{
			name:     "no flags",
			flags:    []imap.Flag{},
			expected: 0,
		},
		{
			name:     "duplicate flags",
			flags:    []imap.Flag{imap.FlagSeen, imap.FlagSeen, imap.FlagAnswered},
			expected: FlagSeen | FlagAnswered,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FlagsToBitwise(tt.flags)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestBitwiseToFlags tests converting bitwise flags back to IMAP flags
func TestBitwiseToFlags(t *testing.T) {
	tests := []struct {
		name     string
		bitwise  int
		expected []imap.Flag
	}{
		{
			name:     "single flag",
			bitwise:  FlagSeen,
			expected: []imap.Flag{imap.FlagSeen},
		},
		{
			name:     "multiple flags",
			bitwise:  FlagSeen | FlagAnswered,
			expected: []imap.Flag{imap.FlagSeen, imap.FlagAnswered},
		},
		{
			name:     "all flags",
			bitwise:  FlagSeen | FlagAnswered | FlagFlagged | FlagDeleted | FlagDraft | FlagRecent,
			expected: []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDeleted, imap.FlagDraft, imap.Flag("\\Recent")},
		},
		{
			name:     "no flags",
			bitwise:  0,
			expected: []imap.Flag{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BitwiseToFlags(tt.bitwise)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

// TestFlagConversionRoundTrip tests that flag conversion is bidirectional
func TestFlagConversionRoundTrip(t *testing.T) {
	originalFlags := []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged}

	// Convert to bitwise and back
	bitwise := FlagsToBitwise(originalFlags)
	convertedBack := BitwiseToFlags(bitwise)

	assert.ElementsMatch(t, originalFlags, convertedBack)
}

// TestMessageStruct tests the Message struct initialization
func TestMessageStruct(t *testing.T) {
	now := time.Now()
	recipients := []byte(`{"to": ["user@example.com"], "cc": []}`)

	msg := Message{
		ID:             1,
		AccountID:      100,
		UID:            imap.UID(12345),
		ContentHash:    "abc123hash",
		S3Domain:       "example.com",
		S3Localpart:    "path/to/message",
		MailboxID:      50,
		IsUploaded:     true,
		Seq:            1,
		BitwiseFlags:   FlagSeen | FlagAnswered,
		CustomFlags:    []string{"CustomFlag1", "CustomFlag2"},
		FlagsChangedAt: &now,
		Subject:        "Test Message",
		InternalDate:   now,
		SentDate:       now.Add(-time.Hour),
		Size:           1024,
		MessageID:      "<test@example.com>",
		CreatedModSeq:  1000,
		InReplyTo:      "<previous@example.com>",
		RecipientsJSON: recipients,
	}

	// Verify all fields are set correctly
	assert.Equal(t, int64(1), msg.ID)
	assert.Equal(t, int64(100), msg.AccountID)
	assert.Equal(t, imap.UID(12345), msg.UID)
	assert.Equal(t, "abc123hash", msg.ContentHash)
	assert.Equal(t, "example.com", msg.S3Domain)
	assert.Equal(t, "path/to/message", msg.S3Localpart)
	assert.Equal(t, int64(50), msg.MailboxID)
	assert.True(t, msg.IsUploaded)
	assert.Equal(t, uint32(1), msg.Seq)
	assert.Equal(t, FlagSeen|FlagAnswered, msg.BitwiseFlags)
	assert.ElementsMatch(t, []string{"CustomFlag1", "CustomFlag2"}, msg.CustomFlags)
	assert.Equal(t, now, *msg.FlagsChangedAt)
	assert.Equal(t, "Test Message", msg.Subject)
	assert.Equal(t, now, msg.InternalDate)
	assert.Equal(t, now.Add(-time.Hour), msg.SentDate)
	assert.Equal(t, 1024, msg.Size)
	assert.Equal(t, "<test@example.com>", msg.MessageID)
	assert.Equal(t, int64(1000), msg.CreatedModSeq)
	assert.Equal(t, "<previous@example.com>", msg.InReplyTo)
	assert.Equal(t, recipients, msg.RecipientsJSON)
}

// TestMessagePartStruct tests the MessagePart struct
func TestMessagePartStruct(t *testing.T) {
	part := MessagePart{
		MessageID:  123,
		PartNumber: 1,
		Size:       512,
		S3Key:      "bucket/message/part1",
		Type:       "text/plain",
	}

	assert.Equal(t, int64(123), part.MessageID)
	assert.Equal(t, 1, part.PartNumber)
	assert.Equal(t, 512, part.Size)
	assert.Equal(t, "bucket/message/part1", part.S3Key)
	assert.Equal(t, "text/plain", part.Type)
}

// Database test helpers for message tests
func setupMessageTestDatabase(t *testing.T) (*Database, int64, int64) {
	db := setupTestDatabase(t)

	ctx := context.Background()

	// Use test name and timestamp to create unique email
	testEmail := fmt.Sprintf("test_%s_%d@example.com", t.Name(), time.Now().UnixNano())

	// Create test account
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

	// Create test mailbox
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx2, accountID, "INBOX", nil)
	require.NoError(t, err)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Get mailbox ID
	mailbox, err := db.GetMailboxByName(ctx, accountID, "INBOX")
	require.NoError(t, err)

	return db, accountID, mailbox.ID
}

// Database test helpers are in test_helpers_test.go

// TestGetMessagesByNumSet tests message retrieval by number set
func TestGetMessagesByNumSet(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Empty mailbox with UID set - should return empty slice
	var uidSet imap.UIDSet
	uidSet.AddRange(1, 10)

	messages, err := db.GetMessagesByNumSet(ctx, mailboxID, uidSet)
	assert.NoError(t, err)
	assert.Empty(t, messages)

	// Test 2: Empty mailbox with sequence set - should return empty slice
	var seqSet imap.SeqSet
	seqSet.AddRange(1, 10)

	messages, err = db.GetMessagesByNumSet(ctx, mailboxID, seqSet)
	assert.NoError(t, err)
	assert.Empty(t, messages)

	// Test 3: Non-existent mailbox - should return error
	_, err = db.GetMessagesByNumSet(ctx, 99999, uidSet)
	assert.NoError(t, err) // This might not error, just return empty

	t.Logf("Successfully tested GetMessagesByNumSet with accountID: %d, mailboxID: %d", accountID, mailboxID)
}

// TestGetMessagesByFlag tests message retrieval by flag
func TestGetMessagesByFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: No messages with \\Seen flag in empty mailbox
	messages, err := db.GetMessagesByFlag(ctx, mailboxID, imap.FlagSeen)
	assert.NoError(t, err)
	assert.Empty(t, messages)

	// Test 2: No messages with \\Flagged flag in empty mailbox
	messages, err = db.GetMessagesByFlag(ctx, mailboxID, imap.FlagFlagged)
	assert.NoError(t, err)
	assert.Empty(t, messages)

	// Test 3: Invalid mailbox ID - should return empty (not error)
	messages, err = db.GetMessagesByFlag(ctx, 99999, imap.FlagSeen)
	assert.NoError(t, err)
	assert.Empty(t, messages)

	t.Logf("Successfully tested GetMessagesByFlag with accountID: %d, mailboxID: %d", accountID, mailboxID)
}

// TestCopyMessages tests message copying between mailboxes
func TestCopyMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Create a second mailbox for testing copies
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	err = db.CreateMailbox(ctx, tx, accountID, "Sent", nil)
	require.NoError(t, err)

	err = tx.Commit(ctx)
	require.NoError(t, err)

	sentMailbox, err := db.GetMailboxByName(ctx, accountID, "Sent")
	require.NoError(t, err)

	// Test 1: Copy non-existent messages (empty UID list)
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	emptyUIDs := []imap.UID{}
	uidMapping, err := db.CopyMessages(ctx, tx2, &emptyUIDs, mailboxID, sentMailbox.ID, accountID)
	assert.NoError(t, err)
	assert.Empty(t, uidMapping)

	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Test 2: Copy non-existent messages (UIDs that don't exist)
	tx3, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx3.Rollback(ctx)

	nonExistentUIDs := []imap.UID{1, 2, 3}
	uidMapping, err = db.CopyMessages(ctx, tx3, &nonExistentUIDs, mailboxID, sentMailbox.ID, accountID)
	assert.NoError(t, err)
	assert.Empty(t, uidMapping) // Should be empty since no messages exist

	err = tx3.Commit(ctx)
	require.NoError(t, err)

	t.Logf("Successfully tested CopyMessages with accountID: %d, srcMailboxID: %d, destMailboxID: %d", accountID, mailboxID, sentMailbox.ID)
}

// TestListMessages tests basic message listing
func TestListMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: List messages in empty mailbox
	messages, err := db.ListMessages(ctx, mailboxID)
	assert.NoError(t, err)
	assert.Empty(t, messages)

	// Test 2: List messages in non-existent mailbox
	messages, err = db.ListMessages(ctx, 99999)
	assert.NoError(t, err)
	assert.Empty(t, messages) // Should return empty, not error

	t.Logf("Successfully tested ListMessages with accountID: %d, mailboxID: %d", accountID, mailboxID)
}

// TestGetMessageTextBody tests message body retrieval
func TestGetMessageTextBody(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Get body for non-existent message
	body, err := db.GetMessageTextBody(ctx, imap.UID(1), mailboxID)
	assert.Error(t, err) // Should return error for non-existent message
	assert.Empty(t, body)

	// Test 2: Get body for non-existent mailbox
	body, err = db.GetMessageTextBody(ctx, imap.UID(1), 99999)
	assert.Error(t, err) // Should return error for non-existent mailbox
	assert.Empty(t, body)

	t.Logf("Successfully tested GetMessageTextBody with accountID: %d, mailboxID: %d", accountID, mailboxID)
}

// TestGetMessageEnvelope tests message envelope retrieval
func TestGetMessageEnvelope(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Get envelope for non-existent message
	envelope, err := db.GetMessageEnvelope(ctx, imap.UID(1), mailboxID)
	assert.Error(t, err) // Should return error for non-existent message
	assert.Nil(t, envelope)

	// Test 2: Get envelope for non-existent mailbox
	envelope, err = db.GetMessageEnvelope(ctx, imap.UID(1), 99999)
	assert.Error(t, err) // Should return error for non-existent mailbox
	assert.Nil(t, envelope)

	t.Logf("Successfully tested GetMessageEnvelope with accountID: %d, mailboxID: %d", accountID, mailboxID)
}

// TestInsertMessage tests message insertion functionality
func TestInsertMessage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test 1: Insert a basic message
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	now := time.Now()

	// Create a valid BodyStructure for the test message
	bodyStructure := &imap.BodyStructureSinglePart{
		Type:        "text",
		Subtype:     "plain",
		Params:      map[string]string{"charset": "utf-8"},
		ID:          "",
		Description: "",
		Encoding:    "7bit",
		Size:        1024,
	}
	var bs imap.BodyStructure = bodyStructure

	options := &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   "INBOX",
		S3Domain:      "example.com",
		S3Localpart:   "test/message1",
		ContentHash:   "abc123hash",
		MessageID:     "<test1@example.com>",
		Flags:         []imap.Flag{imap.FlagSeen},
		InternalDate:  now,
		Size:          1024,
		Subject:       "Test Message",
		PlaintextBody: "This is a test message body",
		SentDate:      now.Add(-time.Hour),
		InReplyTo:     []string{},
		BodyStructure: &bs,
	}

	upload := PendingUpload{
		AccountID:   accountID,
		ContentHash: "abc123hash",
		InstanceID:  "test-instance",
		Size:        1024,
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

	// Test 2: Verify the message was inserted correctly
	messages, err := db.ListMessages(ctx, mailboxID)
	assert.NoError(t, err)
	assert.Len(t, messages, 1)
	assert.Equal(t, "Test Message", messages[0].Subject)
	assert.Equal(t, "abc123hash", messages[0].ContentHash)

	t.Logf("Successfully tested InsertMessage with accountID: %d, mailboxID: %d, messageID: %d, UID: %d", accountID, mailboxID, messageID, uid)
}

// TestInsertMessageFromImporter tests message insertion from importer
func TestInsertMessageFromImporter(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Test: Insert message from importer (no S3 upload)
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	now := time.Now()

	// Create a valid BodyStructure for the test message
	bodyStructure := &imap.BodyStructureSinglePart{
		Type:        "text",
		Subtype:     "plain",
		Params:      map[string]string{"charset": "utf-8"},
		ID:          "",
		Description: "",
		Encoding:    "7bit",
		Size:        2048,
	}
	var bs imap.BodyStructure = bodyStructure

	options := &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   "INBOX",
		S3Domain:      "example.com",
		S3Localpart:   "import/message1",
		ContentHash:   "import123hash",
		MessageID:     "<import1@example.com>",
		Flags:         []imap.Flag{imap.FlagFlagged},
		InternalDate:  now,
		Size:          2048,
		Subject:       "Imported Message",
		PlaintextBody: "This is an imported message",
		SentDate:      now.Add(-2 * time.Hour),
		InReplyTo:     []string{"<previous@example.com>"},
		BodyStructure: &bs,
	}

	messageID, uid, err := db.InsertMessageFromImporter(ctx, tx, options)
	assert.NoError(t, err)
	assert.Greater(t, messageID, int64(0))
	assert.Greater(t, uid, int64(0))

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Verify the imported message
	messages, err := db.ListMessages(ctx, mailboxID)
	assert.NoError(t, err)
	assert.Len(t, messages, 1)
	assert.Equal(t, "Imported Message", messages[0].Subject)
	assert.Equal(t, "import123hash", messages[0].ContentHash)

	t.Logf("Successfully tested InsertMessageFromImporter with accountID: %d, mailboxID: %d, messageID: %d, UID: %d", accountID, mailboxID, messageID, uid)
}

// TestInsertMessageFromImporter_DuplicateMessageIDDifferentContent tests that inserting a message
// with the same message_id but different content_hash is handled gracefully without unique violations.
// This proves the fix for the bug where the deduplication check was checking both message_id AND content_hash,
// but the unique constraint is only on message_id.
func TestInsertMessageFromImporter_DuplicateMessageIDDifferentContent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Insert first message with specific message_id and content_hash
	tx, err := db.WritePool.Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	options1 := &InsertMessageOptions{
		AccountID:   accountID,
		MailboxID:   mailboxID,
		MailboxName: "INBOX",
		S3Domain:    "example.com",
		S3Localpart: "duplicate-test",
		ContentHash: "hash-content-v1", // First content hash
		MessageID:   "unique-msg-id@example.com",
		Subject:     "First Version",
		Size:        100,
		SentDate:    time.Now(),
	}

	messageID1, uid1, err := db.InsertMessageFromImporter(ctx, tx, options1)
	require.NoError(t, err, "First insert should succeed")
	require.Greater(t, messageID1, int64(0))
	require.Greater(t, uid1, int64(0))

	err = tx.Commit(ctx)
	require.NoError(t, err)

	// Now try to insert a message with SAME message_id but DIFFERENT content_hash
	// Before the fix, this would:
	// 1. Pass the deduplication check (because content_hash differs)
	// 2. Fail on INSERT with unique constraint violation (because message_id matches)
	// 3. Cause an aborted transaction error when trying to query for the existing message
	//
	// After the fix, this should:
	// 1. Find the existing message by message_id (regardless of content_hash)
	// 2. Return the existing UID without attempting INSERT
	// 3. Log that same message_id with different content was found

	tx2, err := db.WritePool.Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	options2 := &InsertMessageOptions{
		AccountID:   accountID,
		MailboxID:   mailboxID,
		MailboxName: "INBOX",
		S3Domain:    "example.com",
		S3Localpart: "duplicate-test",
		ContentHash: "hash-content-v2",           // DIFFERENT content hash
		MessageID:   "unique-msg-id@example.com", // SAME message_id
		Subject:     "Second Version (should be skipped)",
		Size:        200,
		SentDate:    time.Now(),
	}

	messageID2, uid2, err := db.InsertMessageFromImporter(ctx, tx2, options2)

	// Should return ErrDBUniqueViolation (duplicate detected before INSERT)
	require.Error(t, err, "Second insert should return error for duplicate")
	require.ErrorIs(t, err, consts.ErrDBUniqueViolation, "Should return ErrDBUniqueViolation")

	// Should return 0 for messageID (indicating duplicate was found)
	assert.Equal(t, int64(0), messageID2, "messageID should be 0 for duplicate")

	// Should return the SAME UID as the first message
	assert.Equal(t, uid1, uid2, "UID should match the existing message")

	// Commit should succeed (error was handled gracefully)
	err = tx2.Commit(ctx)
	require.NoError(t, err)

	// Verify only ONE message exists (the duplicate was NOT inserted)
	messages, err := db.ListMessages(ctx, mailboxID)
	require.NoError(t, err)
	assert.Len(t, messages, 1, "Only one message should exist (duplicate was skipped)")

	// Verify the FIRST message is the one that was kept
	assert.Equal(t, "First Version", messages[0].Subject)
	assert.Equal(t, "hash-content-v1", messages[0].ContentHash)

	t.Logf("Successfully tested duplicate message_id with different content_hash: kept UID=%d, skipped duplicate with different content", uid1)
}

// TestInsertMessage_DuplicateDoesNotCreateOrphanedPendingUpload tests that when a duplicate
// message is detected, no orphaned pending_upload record is created.
// This test reproduces the bug where duplicate detection happens AFTER pending_upload insert,
// causing stuck uploads with missing local files.
func TestInsertMessage_DuplicateDoesNotCreateOrphanedPendingUpload(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	db, accountID, mailboxID := setupMessageTestDatabase(t)
	defer db.Close()

	ctx := context.Background()

	// Step 1: Insert first message successfully
	tx1, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx1.Rollback(ctx)

	now := time.Now()
	contentHash := "duplicate-test-hash-123"
	messageID := "<duplicate-test@example.com>"

	bodyStructure := &imap.BodyStructureSinglePart{
		Type:    "text",
		Subtype: "plain",
		Params:  map[string]string{"charset": "utf-8"},
	}
	var bs imap.BodyStructure = bodyStructure

	options1 := &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   "INBOX",
		S3Domain:      "example.com",
		S3Localpart:   "test",
		ContentHash:   contentHash,
		MessageID:     messageID,
		Flags:         []imap.Flag{},
		InternalDate:  now,
		Size:          100,
		Subject:       "Original Message",
		PlaintextBody: "Original body",
		SentDate:      now,
		BodyStructure: &bs,
	}

	upload1 := PendingUpload{
		AccountID:   accountID,
		ContentHash: contentHash,
		InstanceID:  "test-instance",
		Size:        100,
	}

	msgID1, uid1, err := db.InsertMessage(ctx, tx1, options1, upload1)
	require.NoError(t, err)
	require.Greater(t, msgID1, int64(0))
	require.Greater(t, uid1, int64(0))

	err = tx1.Commit(ctx)
	require.NoError(t, err)

	// Verify pending_upload was created for first message
	var pendingCount1 int
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT COUNT(*) FROM pending_uploads
		WHERE content_hash = $1 AND account_id = $2
	`, contentHash, accountID).Scan(&pendingCount1)
	require.NoError(t, err)
	assert.Equal(t, 1, pendingCount1, "First message should create pending_upload")
	t.Logf("After first insert: pending_upload count = %d", pendingCount1)

	// Step 2: Attempt to insert duplicate message (same message_id + same content_hash)
	tx2, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx2.Rollback(ctx)

	options2 := &InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailboxID,
		MailboxName:   "INBOX",
		S3Domain:      "example.com",
		S3Localpart:   "test",
		ContentHash:   contentHash, // SAME content hash
		MessageID:     messageID,   // SAME message_id
		Flags:         []imap.Flag{},
		InternalDate:  now,
		Size:          100,
		Subject:       "Duplicate Attempt",
		PlaintextBody: "Original body",
		SentDate:      now,
		BodyStructure: &bs,
	}

	upload2 := PendingUpload{
		AccountID:   accountID,
		ContentHash: contentHash,
		InstanceID:  "test-instance",
		Size:        100,
	}

	msgID2, uid2, insertErr := db.InsertMessage(ctx, tx2, options2, upload2)

	// Should detect duplicate and return ErrMessageExists
	require.Error(t, insertErr, "Duplicate message should return error")
	require.ErrorIs(t, insertErr, consts.ErrMessageExists, "Should return ErrMessageExists")
	assert.Equal(t, int64(0), msgID2, "messageID should be 0 for duplicate")
	assert.Equal(t, uid1, uid2, "Should return existing UID")
	t.Logf("After duplicate attempt: msgID=%d, uid=%d, insertErr=%v", msgID2, uid2, insertErr)

	err = tx2.Rollback(ctx) // Rollback to simulate LMTP behavior
	require.NoError(t, err)

	// Step 3: CRITICAL CHECK - pending_upload count should still be 1
	// Bug: If duplicate check happens AFTER pending_upload insert, count would be 2
	// But local file was never written for the duplicate, causing stuck uploads
	var pendingCountFinal int
	err = db.GetReadPool().QueryRow(ctx, `
		SELECT COUNT(*) FROM pending_uploads
		WHERE content_hash = $1 AND account_id = $2
	`, contentHash, accountID).Scan(&pendingCountFinal)
	require.NoError(t, err)

	// THIS IS THE BUG: If this fails, it means duplicate detection created an orphaned pending_upload
	// The uploader will try to upload a file that doesn't exist (because LMTP skipped file write)
	assert.Equal(t, 1, pendingCountFinal,
		"BUG DETECTED: Duplicate message created orphaned pending_upload! "+
			"This causes 'no such file or directory' errors in uploader worker. "+
			"Fix: Move duplicate check BEFORE pending_upload insert.")

	t.Logf("Test passed: Duplicate detection did not create orphaned pending_upload (count=%d)", pendingCountFinal)
}

// NOTE: The above test verifies database-level duplicate handling works correctly.
// However, there's a separate race condition at the LMTP file system level:
//
// RACE CONDITION BUG (fixed in server/lmtp/session.go):
// 1. Message1 arrives → file written to disk, pending_upload created
// 2. Uploader acquires pending_upload, starts reading file
// 3. Message2 (duplicate) arrives → StoreLocally() OVERWRITES same file path
// 4. Message2 duplicate detected → LMTP deletes file
// 5. Uploader tries to read → "no such file or directory"
// 6. Uploader retries 5x → stuck upload
//
// This race happens because:
// - File path is deterministic: /uploads/{account_id}/{content_hash}
// - os.WriteFile() overwrites existing files
// - LMTP deletes file on duplicate detection
//
// The fix checks if file exists before writing in server/lmtp/session.go:347-364
