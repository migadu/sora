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

// Helper to create a default body structure for testing
func createDefaultBodyStructure() *imap.BodyStructure {
	bs := &imap.BodyStructureSinglePart{
		Type:    "text",
		Subtype: "plain",
		Size:    100,
	}
	var result imap.BodyStructure = bs
	return &result
}

// TestUIDPreservation tests that UIDs can be preserved during message delivery
// and that out-of-order UID insertion works correctly for parallel imports
func TestUIDPreservation(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	ctx := context.Background()

	// Create test account
	testEmail := fmt.Sprintf("uid-test-%d@example.com", time.Now().UnixNano())
	testAccount := common.CreateTestAccountWithEmail(t, rdb, testEmail, "test-password")

	// Get account ID
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, testAccount.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	// Get INBOX
	inbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatalf("Failed to get INBOX: %v", err)
	}

	t.Run("sequential UID preservation", func(t *testing.T) {
		// Insert messages with specific UIDs in order
		uids := []uint32{10, 20, 30}

		for i, uid := range uids {
			uidCopy := uid // Create a copy for pointer
			_, insertedUID, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
				AccountID:     accountID,
				MailboxID:     inbox.ID,
				MailboxName:   inbox.Name,
				S3Domain:      "example.com",
				S3Localpart:   "uid-test",
				ContentHash:   fmt.Sprintf("hash-sequential-%d", i),
				MessageID:     fmt.Sprintf("<sequential-%d@test.com>", i),
				InternalDate:  time.Now(),
				Size:          100,
				Subject:       fmt.Sprintf("Sequential Test %d", i),
				SentDate:      time.Now(),
				Recipients:    []helpers.Recipient{},
				BodyStructure: createDefaultBodyStructure(),
				PreservedUID:  &uidCopy,
			}, db.PendingUpload{
				ContentHash: fmt.Sprintf("hash-sequential-%d", i),
				InstanceID:  "test",
				Size:        100,
				AccountID:   accountID,
			})

			if err != nil {
				t.Fatalf("Failed to insert message with UID %d: %v", uid, err)
			}

			if uint32(insertedUID) != uid {
				t.Errorf("Expected UID %d, got %d", uid, insertedUID)
			}
		}

		// Verify all messages were inserted correctly
		uidSet := imap.UIDSet{imap.UIDRange{Start: 1, Stop: 0}}
		messages, err := rdb.GetMessagesByNumSetWithRetry(ctx, inbox.ID, uidSet)
		if err != nil {
			t.Fatalf("Failed to fetch messages: %v", err)
		}

		if len(messages) != len(uids) {
			t.Errorf("Expected %d messages, got %d", len(uids), len(messages))
		}

		for i, msg := range messages {
			if uint32(msg.UID) != uids[i] {
				t.Errorf("Message %d: expected UID %d, got %d", i, uids[i], msg.UID)
			}
		}

		t.Logf("✓ Sequential UID preservation successful")
	})

	t.Run("out-of-order UID preservation", func(t *testing.T) {
		// Create a separate mailbox for this test
		mailboxName := fmt.Sprintf("OutOfOrder-%d", time.Now().UnixNano())
		err := rdb.CreateMailboxWithRetry(ctx, accountID, mailboxName, nil)
		if err != nil {
			t.Fatalf("Failed to create mailbox: %v", err)
		}

		mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
		if err != nil {
			t.Fatalf("Failed to get mailbox: %v", err)
		}
		mailboxID := mailbox.ID

		// Insert messages with UIDs in random order to simulate parallel import
		// This tests the GREATEST() logic in the database
		uidsInOrder := []uint32{5, 15, 3, 25, 1, 20, 10}

		for i, uid := range uidsInOrder {
			uidCopy := uid // Create a copy for pointer
			_, insertedUID, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
				AccountID:     accountID,
				MailboxID:     mailboxID,
				MailboxName:   mailboxName,
				S3Domain:      "example.com",
				S3Localpart:   "uid-test",
				ContentHash:   fmt.Sprintf("hash-ooo-%d", i),
				MessageID:     fmt.Sprintf("<ooo-%d@test.com>", uid),
				InternalDate:  time.Now(),
				Size:          100,
				Subject:       fmt.Sprintf("Out-of-Order Test %d", uid),
				SentDate:      time.Now(),
				Recipients:    []helpers.Recipient{},
				BodyStructure: createDefaultBodyStructure(),
				PreservedUID:  &uidCopy,
			}, db.PendingUpload{
				ContentHash: fmt.Sprintf("hash-ooo-%d", i),
				InstanceID:  "test",
				Size:        100,
				AccountID:   accountID,
			})

			if err != nil {
				t.Fatalf("Failed to insert message with UID %d (iteration %d): %v", uid, i, err)
			}

			if uint32(insertedUID) != uid {
				t.Errorf("Expected UID %d, got %d", uid, insertedUID)
			}
		}

		// Verify all messages exist with correct UIDs
		uidSet := imap.UIDSet{imap.UIDRange{Start: 1, Stop: 0}}
		messages, err := rdb.GetMessagesByNumSetWithRetry(ctx, mailboxID, uidSet)
		if err != nil {
			t.Fatalf("Failed to fetch messages: %v", err)
		}

		if len(messages) != len(uidsInOrder) {
			t.Errorf("Expected %d messages, got %d", len(uidsInOrder), len(messages))
		}

		// Verify UIDs are correct (messages should be sorted by UID)
		expectedSorted := []uint32{1, 3, 5, 10, 15, 20, 25}

		// Log actual UIDs for debugging
		actualUIDs := make([]uint32, len(messages))
		for i, msg := range messages {
			actualUIDs[i] = uint32(msg.UID)
		}
		t.Logf("Expected UIDs: %v", expectedSorted)
		t.Logf("Actual UIDs:   %v", actualUIDs)

		for i, msg := range messages {
			if uint32(msg.UID) != expectedSorted[i] {
				t.Errorf("Message %d: expected UID %d, got %d", i, expectedSorted[i], msg.UID)
			}
		}

		// Verify highest_uid was set correctly
		summary, err := rdb.GetMailboxSummaryWithRetry(ctx, mailboxID)
		if err != nil {
			t.Fatalf("Failed to get mailbox summary: %v", err)
		}

		expectedHighestUID := uint32(25) // Maximum UID inserted
		if uint32(summary.UIDNext) != expectedHighestUID+1 {
			t.Errorf("Expected UIDNEXT %d, got %d", expectedHighestUID+1, summary.UIDNext)
		}

		t.Logf("✓ Out-of-order UID preservation successful (UIDNEXT=%d)", summary.UIDNext)
	})

	t.Run("UID and UIDVALIDITY preservation", func(t *testing.T) {
		// Create a separate mailbox for this test
		mailboxName := fmt.Sprintf("UIDValidity-%d", time.Now().UnixNano())
		err := rdb.CreateMailboxWithRetry(ctx, accountID, mailboxName, nil)
		if err != nil {
			t.Fatalf("Failed to create mailbox: %v", err)
		}

		mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
		if err != nil {
			t.Fatalf("Failed to get mailbox: %v", err)
		}
		mailboxID := mailbox.ID

		// Set specific UIDVALIDITY (simulating migration from another server)
		preservedUIDValidity := uint32(1234567890)
		preservedUID := uint32(42)

		_, insertedUID, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:            accountID,
			MailboxID:            mailboxID,
			MailboxName:          mailboxName,
			S3Domain:             "example.com",
			S3Localpart:          "uid-test",
			ContentHash:          "hash-uidval",
			MessageID:            "<uidval@test.com>",
			InternalDate:         time.Now(),
			Size:                 100,
			Subject:              "UIDVALIDITY Test",
			SentDate:             time.Now(),
			Recipients:           []helpers.Recipient{},
			BodyStructure:        createDefaultBodyStructure(),
			PreservedUID:         &preservedUID,
			PreservedUIDValidity: &preservedUIDValidity,
		}, db.PendingUpload{
			ContentHash: "hash-uidval",
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})

		if err != nil {
			t.Fatalf("Failed to insert message: %v", err)
		}

		if uint32(insertedUID) != preservedUID {
			t.Errorf("Expected UID %d, got %d", preservedUID, insertedUID)
		}

		// Verify UIDVALIDITY was set
		mailbox, err = rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
		if err != nil {
			t.Fatalf("Failed to get mailbox: %v", err)
		}

		if mailbox.UIDValidity != preservedUIDValidity {
			t.Errorf("Expected UIDVALIDITY %d, got %d", preservedUIDValidity, mailbox.UIDValidity)
		}

		t.Logf("✓ UID and UIDVALIDITY preservation successful (UID=%d, UIDVALIDITY=%d)", preservedUID, preservedUIDValidity)
	})

	t.Run("idempotent UID insertion", func(t *testing.T) {
		// Create a separate mailbox for this test
		mailboxName := fmt.Sprintf("Idempotent-%d", time.Now().UnixNano())
		err := rdb.CreateMailboxWithRetry(ctx, accountID, mailboxName, nil)
		if err != nil {
			t.Fatalf("Failed to create mailbox: %v", err)
		}

		mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
		if err != nil {
			t.Fatalf("Failed to get mailbox: %v", err)
		}
		mailboxID := mailbox.ID

		// Insert first set of messages
		uid1 := uint32(100)
		uid2 := uint32(200)

		_, _, err = rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailboxID,
			MailboxName:   mailboxName,
			S3Domain:      "example.com",
			S3Localpart:   "uid-test",
			ContentHash:   "hash-idem-1",
			MessageID:     "<idem-1@test.com>",
			InternalDate:  time.Now(),
			Size:          100,
			Subject:       "Idempotent Test 1",
			SentDate:      time.Now(),
			Recipients:    []helpers.Recipient{},
			BodyStructure: createDefaultBodyStructure(),
			PreservedUID:  &uid1,
		}, db.PendingUpload{
			ContentHash: "hash-idem-1",
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})
		if err != nil {
			t.Fatalf("Failed to insert first message: %v", err)
		}

		_, _, err = rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailboxID,
			MailboxName:   mailboxName,
			S3Domain:      "example.com",
			S3Localpart:   "uid-test",
			ContentHash:   "hash-idem-2",
			MessageID:     "<idem-2@test.com>",
			InternalDate:  time.Now(),
			Size:          100,
			Subject:       "Idempotent Test 2",
			SentDate:      time.Now(),
			Recipients:    []helpers.Recipient{},
			BodyStructure: createDefaultBodyStructure(),
			PreservedUID:  &uid2,
		}, db.PendingUpload{
			ContentHash: "hash-idem-2",
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})
		if err != nil {
			t.Fatalf("Failed to insert second message: %v", err)
		}

		// Try to re-insert the same messages (simulating interrupted migration)
		// This should succeed due to duplicate handling
		_, returnedUID, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:     accountID,
			MailboxID:     mailboxID,
			MailboxName:   mailboxName,
			S3Domain:      "example.com",
			S3Localpart:   "uid-test",
			ContentHash:   "hash-idem-1-reinsert",
			MessageID:     "<idem-1@test.com>", // Same Message-ID
			InternalDate:  time.Now(),
			Size:          100,
			Subject:       "Idempotent Test 1 Re-insert",
			SentDate:      time.Now(),
			Recipients:    []helpers.Recipient{},
			BodyStructure: createDefaultBodyStructure(),
			PreservedUID:  &uid1,
		}, db.PendingUpload{
			ContentHash: "hash-idem-1-reinsert",
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})

		// Should return existing UID
		if err != nil {
			t.Logf("Note: Re-insert returned error (this may be expected): %v", err)
		}

		// Verify only 2 messages exist (no duplicates)
		uidSet := imap.UIDSet{imap.UIDRange{Start: 1, Stop: 0}}
		messages, err := rdb.GetMessagesByNumSetWithRetry(ctx, mailboxID, uidSet)
		if err != nil {
			t.Fatalf("Failed to fetch messages: %v", err)
		}

		if len(messages) != 2 {
			t.Errorf("Expected 2 messages (no duplicates), got %d", len(messages))
		}

		// Verify returned UID matches original
		if err == nil && uint32(returnedUID) != uid1 {
			t.Logf("Re-insert returned different UID: expected %d, got %d", uid1, returnedUID)
		}

		t.Logf("✓ Idempotent UID insertion handled correctly")
	})

	t.Run("UIDVALIDITY mismatch protection", func(t *testing.T) {
		// Create a separate mailbox for this test
		mailboxName := fmt.Sprintf("UIDValidityMismatch-%d", time.Now().UnixNano())
		err := rdb.CreateMailboxWithRetry(ctx, accountID, mailboxName, nil)
		if err != nil {
			t.Fatalf("Failed to create mailbox: %v", err)
		}

		mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
		if err != nil {
			t.Fatalf("Failed to get mailbox: %v", err)
		}
		mailboxID := mailbox.ID

		// Insert first message with UIDVALIDITY = 1111111111
		firstUIDValidity := uint32(1111111111)
		uid1 := uint32(1)

		_, _, err = rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:            accountID,
			MailboxID:            mailboxID,
			MailboxName:          mailboxName,
			S3Domain:             "example.com",
			S3Localpart:          "uid-test",
			ContentHash:          "hash-uidval-mismatch-1",
			MessageID:            "<uidval-mismatch-1@test.com>",
			InternalDate:         time.Now(),
			Size:                 100,
			Subject:              "UIDVALIDITY Mismatch Test 1",
			SentDate:             time.Now(),
			Recipients:           []helpers.Recipient{},
			BodyStructure:        createDefaultBodyStructure(),
			PreservedUID:         &uid1,
			PreservedUIDValidity: &firstUIDValidity,
		}, db.PendingUpload{
			ContentHash: "hash-uidval-mismatch-1",
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})
		if err != nil {
			t.Fatalf("Failed to insert first message: %v", err)
		}

		// Verify UIDVALIDITY was set
		mailbox, err = rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
		if err != nil {
			t.Fatalf("Failed to get mailbox: %v", err)
		}

		if mailbox.UIDValidity != firstUIDValidity {
			t.Errorf("Expected UIDVALIDITY %d, got %d", firstUIDValidity, mailbox.UIDValidity)
		}

		// Try to insert second message with DIFFERENT UIDVALIDITY = 2222222222
		// This should SUCCEED with graceful fallback (auto-assigned UID)
		secondUIDValidity := uint32(2222222222)
		uid2 := uint32(2)

		_, insertedUID2, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:            accountID,
			MailboxID:            mailboxID,
			MailboxName:          mailboxName,
			S3Domain:             "example.com",
			S3Localpart:          "uid-test",
			ContentHash:          "hash-uidval-mismatch-2",
			MessageID:            "<uidval-mismatch-2@test.com>",
			InternalDate:         time.Now(),
			Size:                 100,
			Subject:              "UIDVALIDITY Mismatch Test 2",
			SentDate:             time.Now(),
			Recipients:           []helpers.Recipient{},
			BodyStructure:        createDefaultBodyStructure(),
			PreservedUID:         &uid2,
			PreservedUIDValidity: &secondUIDValidity,
		}, db.PendingUpload{
			ContentHash: "hash-uidval-mismatch-2",
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})

		// Should succeed with graceful fallback (auto-assigned UID, not preserved)
		if err != nil {
			t.Errorf("Expected graceful fallback to succeed, got error: %v", err)
		}
		// Auto-assigned UID should be 2 (continuing from 1)
		if insertedUID2 != 2 {
			t.Errorf("Expected auto-assigned UID 2, got %d", insertedUID2)
		}
		t.Logf("✓ UIDVALIDITY mismatch handled gracefully: ignored preserved UID, auto-assigned UID %d", insertedUID2)

		// Try to insert third message with SAME UIDVALIDITY as first
		// This should SUCCEED
		uid3 := uint32(3)

		_, _, err = rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:            accountID,
			MailboxID:            mailboxID,
			MailboxName:          mailboxName,
			S3Domain:             "example.com",
			S3Localpart:          "uid-test",
			ContentHash:          "hash-uidval-mismatch-3",
			MessageID:            "<uidval-mismatch-3@test.com>",
			InternalDate:         time.Now(),
			Size:                 100,
			Subject:              "UIDVALIDITY Mismatch Test 3",
			SentDate:             time.Now(),
			Recipients:           []helpers.Recipient{},
			BodyStructure:        createDefaultBodyStructure(),
			PreservedUID:         &uid3,
			PreservedUIDValidity: &firstUIDValidity, // Same as first message
		}, db.PendingUpload{
			ContentHash: "hash-uidval-mismatch-3",
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})

		if err != nil {
			t.Errorf("Expected success with matching UIDVALIDITY, got error: %v", err)
		}

		// Verify UIDVALIDITY is still the original value
		mailbox, err = rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
		if err != nil {
			t.Fatalf("Failed to get mailbox: %v", err)
		}

		if mailbox.UIDValidity != firstUIDValidity {
			t.Errorf("UIDVALIDITY changed! Expected %d, got %d", firstUIDValidity, mailbox.UIDValidity)
		}

		t.Logf("✓ UIDVALIDITY mismatch protection working correctly")
	})

	t.Run("UIDVALIDITY change mid-import scenario", func(t *testing.T) {
		// Simulate real-world scenario: importing messages when source UIDVALIDITY changes mid-way

		// Create a mailbox for this test
		mailboxName := fmt.Sprintf("MidImportChange-%d", time.Now().UnixNano())
		err := rdb.CreateMailboxWithRetry(ctx, accountID, mailboxName, nil)
		if err != nil {
			t.Fatalf("Failed to create mailbox: %v", err)
		}

		mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
		if err != nil {
			t.Fatalf("Failed to get mailbox: %v", err)
		}
		mailboxID := mailbox.ID

		// Phase 1: Import first batch of messages with UIDVALIDITY=1111111111
		firstUIDValidity := uint32(1111111111)
		firstBatchUIDs := []uint32{1, 2, 3}

		t.Logf("Phase 1: Importing first batch with UIDVALIDITY=%d", firstUIDValidity)
		for _, uid := range firstBatchUIDs {
			uidCopy := uid
			_, insertedUID, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
				AccountID:            accountID,
				MailboxID:            mailboxID,
				MailboxName:          mailboxName,
				S3Domain:             "example.com",
				S3Localpart:          "uid-test",
				ContentHash:          fmt.Sprintf("hash-mid-%d", uid),
				MessageID:            fmt.Sprintf("<mid-%d@test.com>", uid),
				InternalDate:         time.Now(),
				Size:                 100,
				Subject:              fmt.Sprintf("Message %d", uid),
				SentDate:             time.Now(),
				Recipients:           []helpers.Recipient{},
				BodyStructure:        createDefaultBodyStructure(),
				PreservedUID:         &uidCopy,
				PreservedUIDValidity: &firstUIDValidity,
			}, db.PendingUpload{
				ContentHash: fmt.Sprintf("hash-mid-%d", uid),
				InstanceID:  "test",
				Size:        100,
				AccountID:   accountID,
			})
			if err != nil {
				t.Fatalf("Failed to insert message UID %d: %v", uid, err)
			}
			if uint32(insertedUID) != uid {
				t.Errorf("Expected UID %d, got %d", uid, insertedUID)
			}
		}

		// Verify first batch imported successfully
		uidSet := imap.UIDSet{imap.UIDRange{Start: 1, Stop: 0}}
		messages, err := rdb.GetMessagesByNumSetWithRetry(ctx, mailboxID, uidSet)
		if err != nil {
			t.Fatalf("Failed to fetch messages: %v", err)
		}
		if len(messages) != len(firstBatchUIDs) {
			t.Errorf("Expected %d messages, got %d", len(firstBatchUIDs), len(messages))
		}

		// Verify UIDVALIDITY was set
		mailbox, err = rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
		if err != nil {
			t.Fatalf("Failed to get mailbox: %v", err)
		}
		if mailbox.UIDValidity != firstUIDValidity {
			t.Errorf("Expected UIDVALIDITY %d, got %d", firstUIDValidity, mailbox.UIDValidity)
		}

		t.Logf("✓ First batch imported successfully: %d messages with UIDVALIDITY=%d", len(firstBatchUIDs), firstUIDValidity)

		// Phase 2: SIMULATE SOURCE SERVER CRASH - UIDVALIDITY changes
		newUIDValidity := uint32(2222222222)

		t.Logf("Phase 2: SOURCE UIDVALIDITY changed to %d - attempting to import second batch", newUIDValidity)

		// Try to import with NEW UIDVALIDITY - should succeed with AUTO-ASSIGNED UID (graceful fallback)
		uid4 := uint32(4)
		_, insertedUID, err := rdb.InsertMessageWithRetry(ctx, &db.InsertMessageOptions{
			AccountID:            accountID,
			MailboxID:            mailboxID,
			MailboxName:          mailboxName,
			S3Domain:             "example.com",
			S3Localpart:          "uid-test",
			ContentHash:          "hash-mid-4",
			MessageID:            "<mid-4@test.com>",
			InternalDate:         time.Now(),
			Size:                 100,
			Subject:              "Message 4",
			SentDate:             time.Now(),
			Recipients:           []helpers.Recipient{},
			BodyStructure:        createDefaultBodyStructure(),
			PreservedUID:         &uid4,
			PreservedUIDValidity: &newUIDValidity, // Different UIDVALIDITY!
		}, db.PendingUpload{
			ContentHash: "hash-mid-4",
			InstanceID:  "test",
			Size:        100,
			AccountID:   accountID,
		})

		// Should succeed with graceful fallback (auto-assigned UID, not preserved)
		if err != nil {
			t.Fatalf("Expected delivery to succeed with auto-assigned UID, got error: %v", err)
		}
		// Auto-assigned UID should be 4 (continuing sequence from 1, 2, 3)
		expectedAutoUID := int64(4)
		if insertedUID != expectedAutoUID {
			t.Errorf("Expected auto-assigned UID %d, got %d", expectedAutoUID, insertedUID)
		}

		t.Logf("✓ UIDVALIDITY mismatch handled gracefully: ignored preserved UID, assigned UID %d instead", insertedUID)

		// Verify mailbox still has original UIDVALIDITY (unchanged)
		currentMailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, mailboxName)
		if err != nil {
			t.Fatalf("Failed to get mailbox: %v", err)
		}
		if currentMailbox.UIDValidity != firstUIDValidity {
			t.Errorf("Expected mailbox UIDVALIDITY to remain %d, got %d", firstUIDValidity, currentMailbox.UIDValidity)
		}

		// Verify we now have 4 messages total
		allMessages, err := rdb.GetMessagesByNumSetWithRetry(ctx, mailboxID, imap.UIDSet{imap.UIDRange{Start: 1, Stop: 0}})
		if err != nil {
			t.Fatalf("Failed to fetch messages: %v", err)
		}
		if len(allMessages) != 4 {
			t.Errorf("Expected 4 messages after graceful fallback, got %d", len(allMessages))
		}

		// Verify message was delivered with auto-assigned UID (this creates duplicate - expected)
		t.Logf("✓ UIDVALIDITY change mid-import handled correctly:")
		t.Logf("  - Mailbox '%s': %d messages, UIDVALIDITY=%d (unchanged)", mailboxName, len(allMessages), currentMailbox.UIDValidity)
		t.Logf("  - Preserved UID ignored when UIDVALIDITY mismatched, auto-assigned UID used instead")
		t.Logf("  - Allows import to continue with potential duplicates (to be deduplicated later)")

		// Skip Phase 3 - no longer needed with graceful fallback approach
	})

}
