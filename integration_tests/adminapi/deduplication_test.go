//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/integration_tests/common"
)

// TestDeduplication tests automatic message deduplication based on content_hash
func TestDeduplication(t *testing.T) {
	ctx := context.Background()
	rdb := common.SetupTestDatabase(t)

	// Create test account
	testEmail := fmt.Sprintf("dedup-test-%d@example.com", time.Now().UnixNano())
	testAccount := common.CreateTestAccountWithEmail(t, rdb, testEmail, "test-password")

	// Get account ID
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, testAccount.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	t.Run("basic deduplication", func(t *testing.T) {
		// Test that duplicate messages (same content_hash) are automatically deduplicated
		mailboxName := fmt.Sprintf("BasicDedup-%d", time.Now().UnixNano())
		err := rdb.CreateMailboxWithRetry(ctx, accountID, mailboxName, nil)
		if err != nil {
			t.Fatalf("Failed to create mailbox: %v", err)
		}

		mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
		if err != nil {
			t.Fatalf("Failed to get mailbox: %v", err)
		}
		mailboxID := mailbox.ID

		contentHash := "basic-dedup-hash"

		// Insert first message
		_, uid1, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailboxID,
			MailboxName:   mailboxName,
			S3Domain:      "example.com",
			S3Localpart:   "dedup-test",
			ContentHash:   contentHash,
			MessageID:     "<dedup-1@test.com>",
			InternalDate:  time.Now(),
			Size:          100,
			Subject:       "Test Message",
			SentDate:      time.Now(),
			Recipients:    []helpers.Recipient{},
			BodyStructure: createDefaultBodyStructure(),
		}, db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})
		if err != nil {
			t.Fatalf("Failed to insert first message: %v", err)
		}

		// Try to insert duplicate (SAME Message-ID and SAME content_hash)
		_, uid2, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailboxID,
			MailboxName:   mailboxName,
			S3Domain:      "example.com",
			S3Localpart:   "dedup-test",
			ContentHash:   contentHash,          // SAME content_hash
			MessageID:     "<dedup-1@test.com>", // SAME Message-ID (true duplicate)
			InternalDate:  time.Now(),
			Size:          100,
			Subject:       "Test Message (duplicate)",
			SentDate:      time.Now(),
			Recipients:    []helpers.Recipient{},
			BodyStructure: createDefaultBodyStructure(),
		}, db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})
		// Expect ErrMessageExists for duplicates
		if err == nil {
			t.Fatalf("Expected ErrMessageExists for duplicate, got nil")
		}
		if err.Error() != "message already exists" {
			t.Fatalf("Expected 'message already exists', got: %v", err)
		}

		// Should return same UID even with error
		if uid1 != uid2 {
			t.Errorf("Expected duplicate to return existing UID %d, got %d", uid1, uid2)
		}

		// Verify only 1 message exists
		messages, err := rdb.GetMessagesByNumSetWithRetry(ctx, mailboxID, imap.UIDSet{imap.UIDRange{Start: 1, Stop: 0}})
		if err != nil {
			t.Fatalf("Failed to fetch messages: %v", err)
		}
		if len(messages) != 1 {
			t.Errorf("Expected 1 message after deduplication, got %d", len(messages))
		}

		t.Logf("✓ Basic deduplication: duplicate (same Message-ID + content_hash) skipped, returned existing UID %d", uid1)
	})

	t.Run("deduplication with UID preservation", func(t *testing.T) {
		// Test deduplication works with preserved UIDs
		mailboxName := fmt.Sprintf("DedupWithUID-%d", time.Now().UnixNano())
		err := rdb.CreateMailboxWithRetry(ctx, accountID, mailboxName, nil)
		if err != nil {
			t.Fatalf("Failed to create mailbox: %v", err)
		}

		mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
		if err != nil {
			t.Fatalf("Failed to get mailbox: %v", err)
		}
		mailboxID := mailbox.ID

		contentHash := "dedup-with-uid-hash"
		uidValidity := uint32(3333333333)
		preservedUID := uint32(42)

		// Insert first message with preserved UID
		_, uid1, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:            accountID,
			MailboxID:            mailboxID,
			MailboxName:          mailboxName,
			S3Domain:             "example.com",
			S3Localpart:          "dedup-test",
			ContentHash:          contentHash,
			MessageID:            "<dedup-uid-1@test.com>",
			InternalDate:         time.Now(),
			Size:                 100,
			Subject:              "Test with UID",
			SentDate:             time.Now(),
			Recipients:           []helpers.Recipient{},
			BodyStructure:        createDefaultBodyStructure(),
			PreservedUID:         &preservedUID,
			PreservedUIDValidity: &uidValidity,
		}, db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})
		if err != nil {
			t.Fatalf("Failed to insert first message: %v", err)
		}
		if uid1 != int64(preservedUID) {
			t.Errorf("Expected preserved UID %d, got %d", preservedUID, uid1)
		}

		// Try to insert duplicate with DIFFERENT preserved UID (but SAME Message-ID + content_hash)
		differentUID := uint32(99)
		_, uid2, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:            accountID,
			MailboxID:            mailboxID,
			MailboxName:          mailboxName,
			S3Domain:             "example.com",
			S3Localpart:          "dedup-test",
			ContentHash:          contentHash,              // SAME content_hash
			MessageID:            "<dedup-uid-1@test.com>", // SAME Message-ID (true duplicate)
			InternalDate:         time.Now(),
			Size:                 100,
			Subject:              "Test with UID (duplicate)",
			SentDate:             time.Now(),
			Recipients:           []helpers.Recipient{},
			BodyStructure:        createDefaultBodyStructure(),
			PreservedUID:         &differentUID, // Different UID!
			PreservedUIDValidity: &uidValidity,
		}, db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})
		// Expect ErrMessageExists for duplicates
		if err == nil {
			t.Fatalf("Expected ErrMessageExists for duplicate, got nil")
		}
		if err.Error() != "message already exists" {
			t.Fatalf("Expected 'message already exists', got: %v", err)
		}

		// Should return ORIGINAL UID (42), not the new one (99)
		if uid2 != uid1 {
			t.Errorf("Expected duplicate to return existing UID %d, got %d", uid1, uid2)
		}

		// Verify only 1 message exists
		messages, err := rdb.GetMessagesByNumSetWithRetry(ctx, mailboxID, imap.UIDSet{imap.UIDRange{Start: 1, Stop: 0}})
		if err != nil {
			t.Fatalf("Failed to fetch messages: %v", err)
		}
		if len(messages) != 1 {
			t.Errorf("Expected 1 message after deduplication, got %d", len(messages))
		}

		t.Logf("✓ Deduplication with UID preservation: preserved UID %d ignored, returned existing UID %d", differentUID, uid1)
	})

	t.Run("no deduplication across mailboxes", func(t *testing.T) {
		// Test that deduplication is per-mailbox (same hash in different mailboxes = OK)
		mailbox1Name := fmt.Sprintf("Mailbox1-%d", time.Now().UnixNano())
		mailbox2Name := fmt.Sprintf("Mailbox2-%d", time.Now().UnixNano())

		err := rdb.CreateMailboxWithRetry(ctx, accountID, mailbox1Name, nil)
		if err != nil {
			t.Fatalf("Failed to create mailbox1: %v", err)
		}
		err = rdb.CreateMailboxWithRetry(ctx, accountID, mailbox2Name, nil)
		if err != nil {
			t.Fatalf("Failed to create mailbox2: %v", err)
		}

		mailbox1, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailbox1Name)
		if err != nil {
			t.Fatalf("Failed to get mailbox1: %v", err)
		}
		mailbox2, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailbox2Name)
		if err != nil {
			t.Fatalf("Failed to get mailbox2: %v", err)
		}

		contentHash := "cross-mailbox-hash"

		// Insert message in mailbox1
		_, uid1, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailbox1.ID,
			MailboxName:   mailbox1Name,
			S3Domain:      "example.com",
			S3Localpart:   "dedup-test",
			ContentHash:   contentHash,
			MessageID:     "<cross-1@test.com>",
			InternalDate:  time.Now(),
			Size:          100,
			Subject:       "Cross-mailbox Test",
			SentDate:      time.Now(),
			Recipients:    []helpers.Recipient{},
			BodyStructure: createDefaultBodyStructure(),
		}, db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})
		if err != nil {
			t.Fatalf("Failed to insert message in mailbox1: %v", err)
		}

		// Insert message with SAME content_hash in mailbox2 - should succeed
		_, uid2, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailbox2.ID,
			MailboxName:   mailbox2Name,
			S3Domain:      "example.com",
			S3Localpart:   "dedup-test",
			ContentHash:   contentHash, // SAME content_hash
			MessageID:     "<cross-2@test.com>",
			InternalDate:  time.Now(),
			Size:          100,
			Subject:       "Cross-mailbox Test (mailbox2)",
			SentDate:      time.Now(),
			Recipients:    []helpers.Recipient{},
			BodyStructure: createDefaultBodyStructure(),
		}, db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})
		if err != nil {
			t.Fatalf("Expected insertion in mailbox2 to succeed, got error: %v", err)
		}

		// UIDs should be the same (both mailboxes start at 1)
		if uid1 != uid2 {
			t.Logf("Note: UID in mailbox1=%d, UID in mailbox2=%d", uid1, uid2)
		}

		// Verify both mailboxes have 1 message each
		messages1, err := rdb.GetMessagesByNumSetWithRetry(ctx, mailbox1.ID, imap.UIDSet{imap.UIDRange{Start: 1, Stop: 0}})
		if err != nil {
			t.Fatalf("Failed to fetch messages from mailbox1: %v", err)
		}
		messages2, err := rdb.GetMessagesByNumSetWithRetry(ctx, mailbox2.ID, imap.UIDSet{imap.UIDRange{Start: 1, Stop: 0}})
		if err != nil {
			t.Fatalf("Failed to fetch messages from mailbox2: %v", err)
		}

		if len(messages1) != 1 {
			t.Errorf("Expected 1 message in mailbox1, got %d", len(messages1))
		}
		if len(messages2) != 1 {
			t.Errorf("Expected 1 message in mailbox2, got %d", len(messages2))
		}

		t.Logf("✓ No deduplication across mailboxes: same content_hash in 2 mailboxes = 2 messages")
	})

	t.Run("deduplication after UIDVALIDITY change", func(t *testing.T) {
		// Test that deduplication prevents duplicates after UIDVALIDITY mismatch
		mailboxName := fmt.Sprintf("DedupAfterUIDVal-%d", time.Now().UnixNano())
		err := rdb.CreateMailboxWithRetry(ctx, accountID, mailboxName, nil)
		if err != nil {
			t.Fatalf("Failed to create mailbox: %v", err)
		}

		mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
		if err != nil {
			t.Fatalf("Failed to get mailbox: %v", err)
		}
		mailboxID := mailbox.ID

		contentHash := "uidval-dedup-hash"
		firstUIDValidity := uint32(1111111111)
		secondUIDValidity := uint32(2222222222)
		preservedUID := uint32(1)

		// Insert first message with UIDVALIDITY=1111111111
		_, uid1, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:            accountID,
			MailboxID:            mailboxID,
			MailboxName:          mailboxName,
			S3Domain:             "example.com",
			S3Localpart:          "dedup-test",
			ContentHash:          contentHash,
			MessageID:            "<uidval-dedup-1@test.com>",
			InternalDate:         time.Now(),
			Size:                 100,
			Subject:              "UIDVALIDITY Test",
			SentDate:             time.Now(),
			Recipients:           []helpers.Recipient{},
			BodyStructure:        createDefaultBodyStructure(),
			PreservedUID:         &preservedUID,
			PreservedUIDValidity: &firstUIDValidity,
		}, db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})
		if err != nil {
			t.Fatalf("Failed to insert first message: %v", err)
		}

		// Try to import SAME message with DIFFERENT UIDVALIDITY (source crashed)
		// Should trigger graceful fallback (ignore preserved UID)
		// BUT deduplication should catch it and return existing UID (SAME Message-ID + content_hash)
		_, uid2, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:            accountID,
			MailboxID:            mailboxID,
			MailboxName:          mailboxName,
			S3Domain:             "example.com",
			S3Localpart:          "dedup-test",
			ContentHash:          contentHash,                 // SAME content_hash
			MessageID:            "<uidval-dedup-1@test.com>", // SAME Message-ID (true duplicate)
			InternalDate:         time.Now(),
			Size:                 100,
			Subject:              "UIDVALIDITY Test (after crash)",
			SentDate:             time.Now(),
			Recipients:           []helpers.Recipient{},
			BodyStructure:        createDefaultBodyStructure(),
			PreservedUID:         &preservedUID,
			PreservedUIDValidity: &secondUIDValidity, // DIFFERENT UIDVALIDITY
		}, db.PendingUpload{
			ContentHash: contentHash,
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})
		// Expect ErrMessageExists for duplicates
		if err == nil {
			t.Fatalf("Expected ErrMessageExists for duplicate, got nil")
		}
		if err.Error() != "message already exists" {
			t.Fatalf("Expected 'message already exists', got: %v", err)
		}

		// Should return existing UID (deduplication prevents duplicate)
		if uid1 != uid2 {
			t.Errorf("Expected deduplication to return existing UID %d, got %d", uid1, uid2)
		}

		// Verify only 1 message exists
		messages, err := rdb.GetMessagesByNumSetWithRetry(ctx, mailboxID, imap.UIDSet{imap.UIDRange{Start: 1, Stop: 0}})
		if err != nil {
			t.Fatalf("Failed to fetch messages: %v", err)
		}
		if len(messages) != 1 {
			t.Errorf("Expected 1 message after deduplication, got %d", len(messages))
		}

		t.Logf("✓ Deduplication after UIDVALIDITY change: graceful fallback + deduplication prevented duplicate")
	})
}
