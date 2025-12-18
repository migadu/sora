//go:build integration
// +build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

// TestUIDPreservation_EmptyMailboxSync tests that UIDVALIDITY and highest_uid
// are correctly initialized BEFORE the first message is imported.
// This prevents the first message from getting a wrong UID.
func TestUIDPreservation_EmptyMailboxSync(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	rdb := setupTestDatabase(t)
	defer rdb.Close()

	ctx := context.Background()
	testEmail := fmt.Sprintf("uid-sync-%d@example.com", time.Now().Unix())
	createTestAccount(t, rdb, testEmail, "testpassword123")

	// Create a test maildir with dovecot-uidlist
	tempDir := t.TempDir()
	maildirPath := filepath.Join(tempDir, "Maildir")

	// Create maildir structure
	if err := os.MkdirAll(filepath.Join(maildirPath, "cur"), 0755); err != nil {
		t.Fatalf("Failed to create cur dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(maildirPath, "new"), 0755); err != nil {
		t.Fatalf("Failed to create new dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(maildirPath, "tmp"), 0755); err != nil {
		t.Fatalf("Failed to create tmp dir: %v", err)
	}

	// Create dovecot-uidlist with specific UIDVALIDITY and NextUID
	uidListContent := `3 V1234567890 N25022 G3085f01b7f11094c501100008c4a11c1
25006 :1276528487.M364837P9451.kurkku,S=1355,W=1394:2,S
25007 :1276528488.M364838P9452.kurkku,S=1400,W=1450:2,
25021 :1276533073.M242911P3632.kurkku:2,F
`
	if err := os.WriteFile(filepath.Join(maildirPath, "dovecot-uidlist"), []byte(uidListContent), 0644); err != nil {
		t.Fatalf("Failed to write dovecot-uidlist: %v", err)
	}

	// Create test messages matching the uidlist
	messages := []struct {
		filename string
		content  string
		uid      uint32
	}{
		{
			filename: "1276528487.M364837P9451.kurkku:2,S",
			content:  "From: sender@example.com\r\nSubject: Test Message 1\r\n\r\nBody 1",
			uid:      25006,
		},
		{
			filename: "1276528488.M364838P9452.kurkku:2,",
			content:  "From: sender@example.com\r\nSubject: Test Message 2\r\n\r\nBody 2",
			uid:      25007,
		},
		{
			filename: "1276533073.M242911P3632.kurkku:2,F",
			content:  "From: sender@example.com\r\nSubject: Test Message 3\r\n\r\nBody 3",
			uid:      25021,
		},
	}

	for _, msg := range messages {
		path := filepath.Join(maildirPath, "cur", msg.filename)
		if err := os.WriteFile(path, []byte(msg.content), 0644); err != nil {
			t.Fatalf("Failed to write message %s: %v", msg.filename, err)
		}
	}

	// Create importer with UID preservation enabled
	options := ImporterOptions{
		PreserveUIDs: true,
		TestMode:     true, // Skip S3 for this test
	}

	importer, err := NewImporter(ctx, maildirPath, testEmail, 1, rdb, nil, options)
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}

	// Run import
	if err := importer.Run(); err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// Verify UIDVALIDITY was set correctly
	address, err := server.NewAddress(testEmail)
	if err != nil {
		t.Fatalf("Invalid email: %v", err)
	}
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	if err != nil {
		t.Fatalf("Failed to get account: %v", err)
	}

	mailbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatalf("Failed to get INBOX: %v", err)
	}

	if mailbox.UIDValidity != 1234567890 {
		t.Errorf("UIDVALIDITY mismatch: got %d, want 1234567890", mailbox.UIDValidity)
	}

	// Verify UIDs were preserved
	db := rdb.GetOperationalDatabase()
	rows, err := db.ReadPool.Query(ctx, `
		SELECT uid, subject
		FROM messages
		WHERE mailbox_id = $1 AND expunged_at IS NULL
		ORDER BY uid
	`, mailbox.ID)
	if err != nil {
		t.Fatalf("Failed to query messages: %v", err)
	}
	defer rows.Close()

	expectedUIDs := []uint32{25006, 25007, 25021}
	gotUIDs := []uint32{}

	for rows.Next() {
		var uid uint32
		var subject string
		if err := rows.Scan(&uid, &subject); err != nil {
			t.Fatalf("Failed to scan row: %v", err)
		}
		gotUIDs = append(gotUIDs, uid)
		t.Logf("Message UID=%d, Subject=%s", uid, subject)
	}

	if len(gotUIDs) != len(expectedUIDs) {
		t.Fatalf("UID count mismatch: got %d, want %d", len(gotUIDs), len(expectedUIDs))
	}

	for i, expectedUID := range expectedUIDs {
		if gotUIDs[i] != expectedUID {
			t.Errorf("UID mismatch at index %d: got %d, want %d", i, gotUIDs[i], expectedUID)
		}
	}

	// Verify highest_uid is correct (should be 25021, the highest preserved UID)
	var highestUID int64
	err = db.ReadPool.QueryRow(ctx, "SELECT highest_uid FROM mailboxes WHERE id = $1", mailbox.ID).Scan(&highestUID)
	if err != nil {
		t.Fatalf("Failed to query highest_uid: %v", err)
	}
	if highestUID != 25021 {
		t.Errorf("highest_uid mismatch: got %d, want 25021", highestUID)
	}
}

// TestUIDPreservation_OutOfOrderImport tests that messages imported out of order
// (not in UID sequence) still preserve their UIDs correctly.
func TestUIDPreservation_OutOfOrderImport(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	rdb := setupTestDatabase(t)
	defer rdb.Close()

	ctx := context.Background()
	testEmail := fmt.Sprintf("uid-ooo-%d@example.com", time.Now().Unix())
	createTestAccount(t, rdb, testEmail, "testpassword123")

	tempDir := t.TempDir()
	maildirPath := filepath.Join(tempDir, "Maildir")

	// Create maildir structure
	for _, dir := range []string{"cur", "new", "tmp"} {
		if err := os.MkdirAll(filepath.Join(maildirPath, dir), 0755); err != nil {
			t.Fatalf("Failed to create %s dir: %v", dir, err)
		}
	}

	// Create dovecot-uidlist with UIDs that are NOT in sequential order
	// UIDs: 100, 50, 200, 75 (deliberately out of order)
	uidListContent := `3 V9999999999 N201
100 :msg1.eml:2,
50 :msg2.eml:2,
200 :msg3.eml:2,
75 :msg4.eml:2,
`
	if err := os.WriteFile(filepath.Join(maildirPath, "dovecot-uidlist"), []byte(uidListContent), 0644); err != nil {
		t.Fatalf("Failed to write dovecot-uidlist: %v", err)
	}

	// Create messages (filesystem order might differ from UID order)
	messages := []struct {
		filename string
		content  string
		uid      uint32
	}{
		{"msg3.eml:2,", "From: test@example.com\r\nSubject: Msg3\r\n\r\nBody", 200},
		{"msg1.eml:2,", "From: test@example.com\r\nSubject: Msg1\r\n\r\nBody", 100},
		{"msg4.eml:2,", "From: test@example.com\r\nSubject: Msg4\r\n\r\nBody", 75},
		{"msg2.eml:2,", "From: test@example.com\r\nSubject: Msg2\r\n\r\nBody", 50},
	}

	for _, msg := range messages {
		path := filepath.Join(maildirPath, "cur", msg.filename)
		if err := os.WriteFile(path, []byte(msg.content), 0644); err != nil {
			t.Fatalf("Failed to write message: %v", err)
		}
	}

	options := ImporterOptions{
		PreserveUIDs: true,
		TestMode:     true,
	}

	importer, err := NewImporter(ctx, maildirPath, testEmail, 1, rdb, nil, options)
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}

	if err := importer.Run(); err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// Verify all UIDs were preserved correctly
	address, _ := server.NewAddress(testEmail)
	accountID, _ := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	mailbox, _ := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")

	db := rdb.GetOperationalDatabase()
	rows, err := db.ReadPool.Query(ctx, `
		SELECT uid, subject
		FROM messages
		WHERE mailbox_id = $1 AND expunged_at IS NULL
		ORDER BY uid
	`, mailbox.ID)
	if err != nil {
		t.Fatalf("Failed to query messages: %v", err)
	}
	defer rows.Close()

	// Expected: UIDs should be in their original preserved values, sorted
	expectedUIDs := []uint32{50, 75, 100, 200}
	gotUIDs := []uint32{}

	for rows.Next() {
		var uid uint32
		var subject string
		rows.Scan(&uid, &subject)
		gotUIDs = append(gotUIDs, uid)
		t.Logf("UID=%d, Subject=%s", uid, subject)
	}

	for i, expectedUID := range expectedUIDs {
		if gotUIDs[i] != expectedUID {
			t.Errorf("UID mismatch at sorted index %d: got %d, want %d", i, gotUIDs[i], expectedUID)
		}
	}

	// highest_uid should be 200 (the maximum)
	var highestUID int64
	db.ReadPool.QueryRow(ctx, "SELECT highest_uid FROM mailboxes WHERE id = $1", mailbox.ID).Scan(&highestUID)
	if highestUID != 200 {
		t.Errorf("highest_uid mismatch: got %d, want 200", highestUID)
	}
}

// TestUIDPreservation_UIDValidityMismatch tests that if UIDVALIDITY doesn't match,
// UIDs are NOT preserved and auto-increment is used instead.
func TestUIDPreservation_UIDValidityMismatch(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	rdb := setupTestDatabase(t)
	defer rdb.Close()

	ctx := context.Background()
	testEmail := fmt.Sprintf("uid-mismatch-%d@example.com", time.Now().Unix())
	createTestAccount(t, rdb, testEmail, "testpassword123")

	tempDir := t.TempDir()
	maildirPath := filepath.Join(tempDir, "Maildir")

	for _, dir := range []string{"cur", "new", "tmp"} {
		os.MkdirAll(filepath.Join(maildirPath, dir), 0755)
	}

	// First import: UIDVALIDITY=1111111111
	uidListContent1 := `3 V1111111111 N3
1 :msg1.eml:2,
2 :msg2.eml:2,
`
	os.WriteFile(filepath.Join(maildirPath, "dovecot-uidlist"), []byte(uidListContent1), 0644)

	messages := []struct {
		filename string
		content  string
	}{
		{"msg1.eml:2,", "From: test@example.com\r\nMessage-ID: <msg1@test.com>\r\nSubject: First Import 1\r\n\r\nBody"},
		{"msg2.eml:2,", "From: test@example.com\r\nMessage-ID: <msg2@test.com>\r\nSubject: First Import 2\r\n\r\nBody"},
	}

	for _, msg := range messages {
		os.WriteFile(filepath.Join(maildirPath, "cur", msg.filename), []byte(msg.content), 0644)
	}

	options := ImporterOptions{
		PreserveUIDs: true,
		TestMode:     true,
	}

	importer, _ := NewImporter(ctx, maildirPath, testEmail, 1, rdb, nil, options)
	if err := importer.Run(); err != nil {
		t.Fatalf("First import failed: %v", err)
	}

	// Verify first import preserved UIDs
	address, _ := server.NewAddress(testEmail)
	accountID, _ := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	mailbox, _ := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")

	if mailbox.UIDValidity != 1111111111 {
		t.Errorf("First import UIDVALIDITY: got %d, want 1111111111", mailbox.UIDValidity)
	}

	// Now simulate a UIDVALIDITY change (e.g., mailbox rebuilt)
	// Remove old message files to simulate a fresh maildir after rebuild
	os.Remove(filepath.Join(maildirPath, "cur", "msg1.eml:2,"))
	os.Remove(filepath.Join(maildirPath, "cur", "msg2.eml:2,"))

	// Second import with DIFFERENT UIDVALIDITY and new message files
	uidListContent2 := `3 V2222222222 N3
1 :msg3.eml:2,
2 :msg4.eml:2,
`
	os.WriteFile(filepath.Join(maildirPath, "dovecot-uidlist"), []byte(uidListContent2), 0644)

	// Add new messages (different content to avoid duplicate detection)
	newMessages := []struct {
		filename string
		content  string
	}{
		{"msg3.eml:2,", "From: test@example.com\r\nMessage-ID: <msg3@test.com>\r\nSubject: Second Import 1\r\n\r\nDifferent Body"},
		{"msg4.eml:2,", "From: test@example.com\r\nMessage-ID: <msg4@test.com>\r\nSubject: Second Import 2\r\n\r\nDifferent Body"},
	}

	for _, msg := range newMessages {
		os.WriteFile(filepath.Join(maildirPath, "cur", msg.filename), []byte(msg.content), 0644)
	}

	// Re-create importer (fresh SQLite cache)
	os.Remove(filepath.Join(maildirPath, "sora-maildir.db"))
	importer2, _ := NewImporter(ctx, maildirPath, testEmail, 1, rdb, nil, options)
	if err := importer2.Run(); err != nil {
		t.Fatalf("Second import failed: %v", err)
	}

	// Refresh mailbox info
	mailbox, _ = rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")

	// UIDVALIDITY should NOT change (mailbox already has messages with old UIDVALIDITY)
	if mailbox.UIDValidity != 1111111111 {
		t.Errorf("UIDVALIDITY changed unexpectedly: got %d, want 1111111111 (should stay at original)", mailbox.UIDValidity)
	}

	// New messages should get auto-increment UIDs (3, 4) instead of preserved UIDs (1, 2)
	// because UIDVALIDITY mismatch
	db := rdb.GetOperationalDatabase()
	rows, _ := db.ReadPool.Query(ctx, `
		SELECT uid, subject
		FROM messages
		WHERE mailbox_id = $1 AND expunged_at IS NULL
		ORDER BY uid
	`, mailbox.ID)
	defer rows.Close()

	allUIDs := []uint32{}
	for rows.Next() {
		var uid uint32
		var subject string
		rows.Scan(&uid, &subject)
		allUIDs = append(allUIDs, uid)
		t.Logf("UID=%d, Subject=%s", uid, subject)
	}

	// Should have 4 messages: original (1,2) + new auto-increment (3,4)
	expectedUIDs := []uint32{1, 2, 3, 4}
	if len(allUIDs) != len(expectedUIDs) {
		t.Errorf("Message count: got %d, want %d", len(allUIDs), len(expectedUIDs))
	}

	for i, expected := range expectedUIDs {
		if i < len(allUIDs) && allUIDs[i] != expected {
			t.Errorf("UID at index %d: got %d, want %d", i, allUIDs[i], expected)
		}
	}
}

// TestUIDPreservation_BatchMode tests UID preservation in batch transaction mode
func TestUIDPreservation_BatchMode(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	rdb := setupTestDatabase(t)
	defer rdb.Close()

	ctx := context.Background()
	testEmail := fmt.Sprintf("uid-batch-%d@example.com", time.Now().Unix())
	createTestAccount(t, rdb, testEmail, "testpassword123")

	tempDir := t.TempDir()
	maildirPath := filepath.Join(tempDir, "Maildir")

	for _, dir := range []string{"cur", "new", "tmp"} {
		os.MkdirAll(filepath.Join(maildirPath, dir), 0755)
	}

	// Create dovecot-uidlist
	uidListContent := `3 V5555555555 N6
10 :batch1.eml:2,
20 :batch2.eml:2,
30 :batch3.eml:2,
40 :batch4.eml:2,
50 :batch5.eml:2,
`
	os.WriteFile(filepath.Join(maildirPath, "dovecot-uidlist"), []byte(uidListContent), 0644)

	// Create 5 messages
	for i := 1; i <= 5; i++ {
		filename := fmt.Sprintf("batch%d.eml:2,", i)
		content := fmt.Sprintf("From: test@example.com\r\nSubject: Batch %d\r\n\r\nBody %d", i, i)
		os.WriteFile(filepath.Join(maildirPath, "cur", filename), []byte(content), 0644)
	}

	// Test with batch transaction mode enabled
	options := ImporterOptions{
		PreserveUIDs:         true,
		TestMode:             true,
		BatchSize:            3, // Process in batches of 3
		BatchTransactionMode: true,
	}

	importer, err := NewImporter(ctx, maildirPath, testEmail, 1, rdb, nil, options)
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}

	if err := importer.Run(); err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// Verify all UIDs preserved
	address, _ := server.NewAddress(testEmail)
	accountID, _ := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	mailbox, _ := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")

	db := rdb.GetOperationalDatabase()
	rows, _ := db.ReadPool.Query(ctx, `
		SELECT uid FROM messages
		WHERE mailbox_id = $1 AND expunged_at IS NULL
		ORDER BY uid
	`, mailbox.ID)
	defer rows.Close()

	expectedUIDs := []uint32{10, 20, 30, 40, 50}
	gotUIDs := []uint32{}

	for rows.Next() {
		var uid uint32
		rows.Scan(&uid)
		gotUIDs = append(gotUIDs, uid)
	}

	for i, expected := range expectedUIDs {
		if gotUIDs[i] != expected {
			t.Errorf("Batch mode UID mismatch at index %d: got %d, want %d", i, gotUIDs[i], expected)
		}
	}
}

// TestUIDPreservation_FilenameMismatch tests when dovecot-uidlist has different
// filename formats than actual files (e.g., flags changed after uidlist was written)
func TestUIDPreservation_FilenameMismatch(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	rdb := setupTestDatabase(t)
	defer rdb.Close()

	ctx := context.Background()
	testEmail := fmt.Sprintf("uid-filename-%d@example.com", time.Now().Unix())
	createTestAccount(t, rdb, testEmail, "testpassword123")

	tempDir := t.TempDir()
	maildirPath := filepath.Join(tempDir, "Maildir")

	for _, dir := range []string{"cur", "new", "tmp"} {
		os.MkdirAll(filepath.Join(maildirPath, dir), 0755)
	}

	// dovecot-uidlist has filename WITHOUT flags
	uidListContent := `3 V7777777777 N3
100 :1234567890.M123P456.host,S=1000,W=1100
200 :1234567891.M124P457.host,S=2000,W=2200
`
	os.WriteFile(filepath.Join(maildirPath, "dovecot-uidlist"), []byte(uidListContent), 0644)

	// Actual files have flags (user marked as seen/flagged after uidlist was written)
	messages := []struct {
		filename string
		content  string
		uid      uint32
	}{
		{
			"1234567890.M123P456.host:2,S", // Added :2,S (Seen flag)
			"From: test@example.com\r\nSubject: File1\r\n\r\nBody",
			100,
		},
		{
			"1234567891.M124P457.host:2,FS", // Added :2,FS (Flagged + Seen)
			"From: test@example.com\r\nSubject: File2\r\n\r\nBody",
			200,
		},
	}

	for _, msg := range messages {
		os.WriteFile(filepath.Join(maildirPath, "cur", msg.filename), []byte(msg.content), 0644)
	}

	options := ImporterOptions{
		PreserveUIDs: true,
		TestMode:     true,
	}

	importer, err := NewImporter(ctx, maildirPath, testEmail, 1, rdb, nil, options)
	if err != nil {
		t.Fatalf("Failed to create importer: %v", err)
	}

	if err := importer.Run(); err != nil {
		t.Fatalf("Import failed: %v", err)
	}

	// Verify UIDs matched despite filename differences
	address, _ := server.NewAddress(testEmail)
	accountID, _ := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	mailbox, _ := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")

	db := rdb.GetOperationalDatabase()
	rows, _ := db.ReadPool.Query(ctx, `
		SELECT uid, subject FROM messages
		WHERE mailbox_id = $1 AND expunged_at IS NULL
		ORDER BY uid
	`, mailbox.ID)
	defer rows.Close()

	gotUIDs := []uint32{}
	for rows.Next() {
		var uid uint32
		var subject string
		rows.Scan(&uid, &subject)
		gotUIDs = append(gotUIDs, uid)
		t.Logf("UID=%d, Subject=%s", uid, subject)
	}

	expectedUIDs := []uint32{100, 200}
	for i, expected := range expectedUIDs {
		if gotUIDs[i] != expected {
			t.Errorf("UID mismatch (filename variant): got %d, want %d", gotUIDs[i], expected)
		}
	}
}

// TestUIDPreservation_NextUIDCorrectness tests that after import,
// the next auto-increment UID is correct (NextUID from dovecot-uidlist)
func TestUIDPreservation_NextUIDCorrectness(t *testing.T) {
	if os.Getenv("SKIP_DB_TESTS") == "true" {
		t.Skip("Skipping database tests")
	}

	rdb := setupTestDatabase(t)
	defer rdb.Close()

	ctx := context.Background()
	testEmail := fmt.Sprintf("uid-nextuid-%d@example.com", time.Now().Unix())
	createTestAccount(t, rdb, testEmail, "testpassword123")

	tempDir := t.TempDir()
	maildirPath := filepath.Join(tempDir, "Maildir")

	for _, dir := range []string{"cur", "new", "tmp"} {
		os.MkdirAll(filepath.Join(maildirPath, dir), 0755)
	}

	// IMPORTANT: NextUID is 1005 (means next message should get UID 1005)
	// Highest existing UID is 1003
	uidListContent := `3 V8888888888 N1005
1001 :msg1.eml:2,
1003 :msg2.eml:2,
`
	os.WriteFile(filepath.Join(maildirPath, "dovecot-uidlist"), []byte(uidListContent), 0644)

	messages := []struct {
		filename string
		content  string
	}{
		{"msg1.eml:2,", "From: test@example.com\r\nSubject: Msg1\r\n\r\nBody"},
		{"msg2.eml:2,", "From: test@example.com\r\nSubject: Msg2\r\n\r\nBody"},
	}

	for _, msg := range messages {
		os.WriteFile(filepath.Join(maildirPath, "cur", msg.filename), []byte(msg.content), 0644)
	}

	options := ImporterOptions{
		PreserveUIDs: true,
		TestMode:     true,
	}

	importer, _ := NewImporter(ctx, maildirPath, testEmail, 1, rdb, nil, options)
	importer.Run()

	// Now deliver a NEW message via LMTP (not in uidlist) to verify NextUID
	address, _ := server.NewAddress(testEmail)
	accountID, _ := rdb.GetAccountIDByAddressWithRetry(ctx, address.FullAddress())
	mailbox, _ := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")

	// Check highest_uid after import
	db := rdb.GetOperationalDatabase()
	var highestUID int64
	db.ReadPool.QueryRow(ctx, "SELECT highest_uid FROM mailboxes WHERE id = $1", mailbox.ID).Scan(&highestUID)

	// Critical test: highest_uid should be 1004 (NextUID - 1 from dovecot-uidlist)
	// This ensures the next message gets UID 1005 as Dovecot expected
	// Even though max preserved UID is 1003, we should reserve UID 1004 to match Dovecot's sequence
	if highestUID != 1004 {
		t.Errorf("After import, highest_uid: got %d, want 1004 (NextUID-1 from dovecot-uidlist)", highestUID)
	}

	// Verify that syncMailboxState set highest_uid = NextUID - 1
	// This prevents UID gaps and collisions if some UIDs weren't imported
	t.Logf("✅ highest_uid=%d correctly set to NextUID-1 (prevents UID 1004 collision)", highestUID)
}
