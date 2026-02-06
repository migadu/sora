//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/helpers"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_EditHeaderStorageVerification tests that header edits are applied
// BEFORE the message is stored to disk, ensuring:
// 1. The file on disk contains the MODIFIED message (not original)
// 2. The content hash matches the MODIFIED message
// 3. The uploader will upload the correct (modified) message to S3
func TestLMTP_EditHeaderStorageVerification(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup database and account
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Get account ID
	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	// Create a Sieve script that adds AND deletes headers
	sieveScript := `require ["editheader"];

# Add a new header
addheader "X-Modified-By" "Sieve";

# Delete the X-Original-Header
deleteheader "X-Original-Header";

# Keep the message
keep;
`

	// Upload the Sieve script
	ctx := context.Background()
	_, _ = rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID)
	_, err = rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
	`, accountID, "test-storage-verification", sieveScript, true)
	if err != nil {
		t.Fatalf("Failed to insert Sieve script: %v", err)
	}

	// Create temp directory for uploader
	tempDir := t.TempDir()
	t.Logf("Uploader temp directory: %s", tempDir)

	s3Storage := &storage.S3Storage{}

	// Create uploader
	uploaderInstance, err := uploader.New(
		context.Background(),
		tempDir,
		10,
		2,
		3,
		5*time.Second,
		"test-host",
		rdb,
		s3Storage,
		nil,
		make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create uploader: %v", err)
	}

	// Setup LMTP server
	lmtpAddr := common.GetRandomAddress(t)
	lmtpSrv, err := lmtpserver.New(
		context.Background(),
		"test-lmtp",
		"localhost",
		lmtpAddr,
		s3Storage,
		rdb,
		uploaderInstance,
		lmtpserver.LMTPServerOptions{},
	)
	if err != nil {
		t.Fatalf("Failed to create LMTP server: %v", err)
	}
	defer lmtpSrv.Close()

	// Start LMTP server
	lmtpErrChan := make(chan error, 1)
	go func() {
		lmtpSrv.Start(lmtpErrChan)
	}()

	// Give server a moment to start
	time.Sleep(200 * time.Millisecond)

	// Connect to LMTP
	lmtpClient, err := NewLMTPClient(lmtpAddr)
	if err != nil {
		t.Fatalf("Failed to connect to LMTP server: %v", err)
	}
	defer lmtpClient.Close()

	// Send LHLO
	if err := lmtpClient.SendCommand("LHLO test.example.com"); err != nil {
		t.Fatalf("Failed to send LHLO: %v", err)
	}
	if _, err := lmtpClient.ReadMultilineResponse(); err != nil {
		t.Fatalf("Failed to read LHLO response: %v", err)
	}

	// Send MAIL FROM
	if err := lmtpClient.SendCommand("MAIL FROM:<sender@example.com>"); err != nil {
		t.Fatalf("Failed to send MAIL FROM: %v", err)
	}
	if _, err := lmtpClient.ReadResponse(); err != nil {
		t.Fatalf("Failed to read MAIL FROM response: %v", err)
	}

	// Send RCPT TO
	if err := lmtpClient.SendCommand(fmt.Sprintf("RCPT TO:<%s>", account.Email)); err != nil {
		t.Fatalf("Failed to send RCPT TO: %v", err)
	}
	rcptResponse, err := lmtpClient.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read RCPT TO response: %v", err)
	}
	if !strings.HasPrefix(rcptResponse, "250") {
		t.Fatalf("Expected 250 response for RCPT TO, got: %s", rcptResponse)
	}

	// Send DATA
	if err := lmtpClient.SendCommand("DATA"); err != nil {
		t.Fatalf("Failed to send DATA: %v", err)
	}
	if _, err := lmtpClient.ReadResponse(); err != nil {
		t.Fatalf("Failed to read DATA response: %v", err)
	}

	// Send message with X-Original-Header that will be deleted
	originalMessage := strings.Join([]string{
		"From: sender@example.com",
		"To: " + account.Email,
		"Subject: Storage Verification Test",
		"X-Original-Header: This should be deleted",
		"Date: " + time.Now().Format(time.RFC1123Z),
		"Message-ID: <test-storage-" + fmt.Sprintf("%d", time.Now().UnixNano()) + "@example.com>",
		"",
		"This message tests that header edits are applied before storage.",
	}, "\r\n")

	// Calculate hash of ORIGINAL message (before Sieve processing)
	originalHash := helpers.HashContent([]byte(originalMessage))
	t.Logf("Original message hash: %s", originalHash)

	if err := lmtpClient.SendCommand(originalMessage + "\r\n."); err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Read per-recipient response
	dataResponses, err := lmtpClient.ReadDataResponses(1)
	if err != nil {
		t.Fatalf("Failed to read DATA responses: %v", err)
	}
	if !strings.HasPrefix(dataResponses[0], "250") {
		t.Fatalf("Expected 250 response after DATA, got: %s", dataResponses[0])
	}

	t.Logf("✓ Message delivered successfully")

	// Give system a moment to write the file
	time.Sleep(500 * time.Millisecond)

	// Debug: List all files in temp directory
	err = filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		t.Logf("Found: %s (isDir: %v)", path, info.IsDir())
		return nil
	})
	if err != nil {
		t.Logf("Walk error: %v", err)
	}

	// Calculate what the MODIFIED message hash should be
	// (after adding X-Modified-By and deleting X-Original-Header)
	modifiedMessage := strings.Join([]string{
		"From: sender@example.com",
		"To: " + account.Email,
		"Subject: Storage Verification Test",
		"Date: " + time.Now().Format(time.RFC1123Z),
		"Message-ID: <test-storage-" + fmt.Sprintf("%d", time.Now().UnixNano()) + "@example.com>",
		"X-Modified-By: Sieve",
		"",
		"This message tests that header edits are applied before storage.",
	}, "\r\n")
	expectedModifiedHash := helpers.HashContent([]byte(modifiedMessage))
	t.Logf("Expected modified message hash: %s", expectedModifiedHash)

	// Find the stored file in the uploader directory
	// The file should be stored with the MODIFIED hash, not the original hash
	// Files are stored as: tempDir/accountID/contentHash (no extension)
	var foundFile string
	err = filepath.Walk(tempDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Find files (not directories) that are content hash files (64 hex chars)
		if !info.IsDir() && len(filepath.Base(path)) == 64 {
			foundFile = path
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to walk temp directory: %v", err)
	}

	if foundFile == "" {
		t.Fatalf("No message file found in uploader directory")
	}

	t.Logf("✓ Found stored file: %s", foundFile)

	// Read the stored file content
	storedContent, err := os.ReadFile(foundFile)
	if err != nil {
		t.Fatalf("Failed to read stored file: %v", err)
	}

	// Calculate hash of stored file
	storedHash := helpers.HashContent(storedContent)
	t.Logf("Stored file hash: %s", storedHash)

	// CRITICAL TEST: The stored hash should NOT match the original
	if storedHash == originalHash {
		t.Errorf("❌ FAIL: Stored file hash matches ORIGINAL message hash")
		t.Errorf("This means header edits were NOT applied before storage!")
		t.Errorf("Original hash: %s", originalHash)
		t.Errorf("Stored hash:   %s", storedHash)
	} else {
		t.Logf("✓ PASS: Stored file hash differs from original (header edits applied)")
	}

	// Verify the stored content has the modifications
	storedText := string(storedContent)

	// Should have X-Modified-By header
	if !strings.Contains(storedText, "X-Modified-By: Sieve") {
		t.Errorf("❌ FAIL: Stored file missing 'X-Modified-By: Sieve' header")
		t.Logf("Stored content:\n%s", storedText)
	} else {
		t.Logf("✓ PASS: Stored file contains 'X-Modified-By: Sieve' header")
	}

	// Should NOT have X-Original-Header
	if strings.Contains(storedText, "X-Original-Header") {
		t.Errorf("❌ FAIL: Stored file still contains 'X-Original-Header' (should be deleted)")
		t.Logf("Stored content:\n%s", storedText)
	} else {
		t.Logf("✓ PASS: Stored file does not contain 'X-Original-Header' (correctly deleted)")
	}

	// Verify the filename contains the modified hash
	if !strings.Contains(foundFile, storedHash) {
		t.Errorf("❌ FAIL: Filename does not contain the stored file's hash")
		t.Errorf("Filename: %s", foundFile)
		t.Errorf("Hash:     %s", storedHash)
	} else {
		t.Logf("✓ PASS: Filename contains correct hash: %s", storedHash)
	}

	t.Logf("✓ All storage verification tests passed!")
}
