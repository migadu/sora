//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/server"
)

// TestUIDSafety_PreExistingMailbox ensures that importing into a non-empty mailbox
// with mismatching UIDVALIDITY safely falls back to auto-increment UIDs
// and preserves the existing UIDVALIDITY.
func TestUIDSafety_PreExistingMailbox(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	rdb := setupTestDatabase(t)
	defer rdb.Close()

	ctx := context.Background()
	testEmail := fmt.Sprintf("uid-safety-%d@example.com", time.Now().Unix())
	createTestAccount(t, rdb, testEmail, "testpassword123")

	// 1. Create INBOX and add a message via "normal delivery" (DB Insert)
	// This establishes an initial UIDVALIDITY and highest_uid
	address, err := server.NewAddress(testEmail)
	if err != nil {
		t.Fatalf("Invalid email: %v", err)
	}
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	if err != nil {
		t.Fatalf("Failed to get account: %v", err)
	}

	// Create mailbox
	err = rdb.CreateMailboxWithRetry(ctx, accountID, "INBOX", nil)
	if err != nil {
		t.Fatalf("Failed to create INBOX: %v", err)
	}

	mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatalf("Failed to get INBOX: %v", err)
	}

	originalUIDValidity := mailbox.UIDValidity
	t.Logf("Initial Mailbox UIDVALIDITY: %d", originalUIDValidity)

	// Insert a message (simulating LMTP delivery)
	// This message will have UID 1
	msgID := fmt.Sprintf("<existing-%d@test.com>", time.Now().UnixNano())

	bsPart := &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
	var bs imap.BodyStructure = bsPart

	insertOpts := &db.InsertMessageOptions{
		AccountID:     accountID,
		MailboxID:     mailbox.ID,
		MailboxName:   mailbox.Name,
		MessageID:     msgID,
		ContentHash:   "hash1", // Dummy hash
		S3Domain:      address.Domain(),
		S3Localpart:   address.LocalPart(),
		Subject:       "Existing Message",
		SentDate:      time.Now(),
		InternalDate:  time.Now(),
		Size:          100,
		Recipients:    []helpers.Recipient{{Name: "User", EmailAddress: testEmail, AddressType: "to"}},
		BodyStructure: &bs,
		PlaintextBody: "Existing body",
		Flags:         []imap.Flag{},
	}
	// We need a dummy PendingUpload for InsertMessageWithRetry
	pendingUpload := db.PendingUpload{
		InstanceID:  "test-instance",
		ContentHash: "hash1",
		Size:        100,
		AccountID:   accountID,
	}

	_, uid, err := rdb.InsertMessageWithRetry(ctx, insertOpts, pendingUpload)
	if err != nil {
		t.Fatalf("Failed to insert existing message: %v", err)
	}
	t.Logf("Inserted existing message with UID: %d", uid)
	if uid != 1 {
		t.Logf("Warning: Expected initial UID to be 1, got %d", uid)
	}

	// 2. Prepare a Maildir to import
	// It has a dovecot-uidlist with a DIFFERENT UIDVALIDITY and some preserved UIDs
	tempDir := t.TempDir()
	maildirPath := filepath.Join(tempDir, "Maildir")
	for _, dir := range []string{"cur", "new", "tmp"} {
		os.MkdirAll(filepath.Join(maildirPath, dir), 0755)
	}

	// UIDVALIDITY mismatch: (originalUIDValidity + 999)
	// Mismatch is practically guaranteed since original is time-based.
	// We use a fixed one here to be sure it's likely different, or force it.
	dovecotUIDValidity := originalUIDValidity + 999

	// dovecot-uidlist content
	// We define UIDs 10 and 20.
	uidListContent := fmt.Sprintf("3 V%d N21\n10 :import1.eml:2,\n20 :import2.eml:2,\n", dovecotUIDValidity)
	os.WriteFile(filepath.Join(maildirPath, "dovecot-uidlist"), []byte(uidListContent), 0644)

	// Create message files
	msgs := []struct {
		filename string
		content  string
	}{
		{"import1.eml:2,", "From: import@test.com\r\nSubject: Import 1\r\n\r\nBody 1"},
		{"import2.eml:2,", "From: import@test.com\r\nSubject: Import 2\r\n\r\nBody 2"},
	}
	for _, m := range msgs {
		os.WriteFile(filepath.Join(maildirPath, "cur", m.filename), []byte(m.content), 0644)
	}

	// 3. Run Import with PreserveUIDs = true
	options := ImporterOptions{
		PreserveUIDs: true,
		TestMode:     true, // Skip S3
	}

	importer, err := NewImporter(ctx, maildirPath, testEmail, 1, rdb, nil, options)
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}

	// Note: We expect warnings in logs about UIDVALIDITY mismatch
	if err := importer.Run(); err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// 4. Verify Results

	// Refetch mailbox to check UIDVALIDITY
	updatedMailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatalf("Failed to get updated mailbox: %v", err)
	}

	// Assertion: UIDVALIDITY must NOT change
	if updatedMailbox.UIDValidity != originalUIDValidity {
		t.Errorf("Safety violation: UIDVALIDITY changed! Original=%d, New=%d (Expected to preserve Original due to mismatch)",
			originalUIDValidity, updatedMailbox.UIDValidity)
	} else {
		t.Logf("✅ Safety check passed: UIDVALIDITY preserved (%d)", updatedMailbox.UIDValidity)
	}

	// Fetch all messages to check UIDs
	dbOps := rdb.GetOperationalDatabase()
	rows, err := dbOps.ReadPool.Query(ctx, `
		SELECT uid, subject FROM messages 
		WHERE mailbox_id = $1 AND expunged_at IS NULL 
		ORDER BY uid
	`, updatedMailbox.ID)
	if err != nil {
		t.Fatalf("Failed to query messages: %v", err)
	}
	defer rows.Close()

	var uids []uint32
	var subjects []string
	for rows.Next() {
		var u uint32
		var s string
		rows.Scan(&u, &s)
		uids = append(uids, u)
		subjects = append(subjects, s)
	}

	t.Logf("Final UIDs in mailbox: %v", uids)

	// Expectation:
	// - Existing message (UID ~1)
	// - Imported messages should have new auto-increment UIDs (e.g. 2, 3), NOT 10 and 20.
	//   Because UIDVALIDITY mismatch causes fallback to auto-increment.

	// Check that we have 3 messages total
	if len(uids) != 3 {
		t.Errorf("Expected 3 messages, got %d", len(uids))
	}

	// Check that the imported UIDs are NOT 10 and 20
	// (Assuming start UID was 1, next ones should be 2 and 3)
	for i, u := range uids {
		if u == 10 || u == 20 {
			t.Errorf("Safety violation: Message '%s' got preserved UID %d despite UIDVALIDITY mismatch!", subjects[i], u)
		}
	}

	// Verify highest_uid matches max(uids)
	var highestUID int64
	dbOps.ReadPool.QueryRow(ctx, "SELECT highest_uid FROM mailboxes WHERE id = $1", mailbox.ID).Scan(&highestUID)

	maxUID := uids[len(uids)-1]
	if int64(maxUID) != highestUID {
		t.Errorf("highest_uid mismatch: got %d, want %d", highestUID, maxUID)
	} else {
		t.Logf("✅ highest_uid correctly updated to %d", highestUID)
	}
}
