//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	imapserver "github.com/migadu/sora/server/imap"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_SieveScriptFailureStillDeliversMessage tests that if a Sieve script
// fails to parse or execute, the message is still delivered to INBOX.
// This ensures we never lose mail due to Sieve errors.
func TestLMTP_SieveScriptFailureStillDeliversMessage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup database and account
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Get account ID
	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	// Create an INVALID Sieve script that will fail to parse
	invalidSieveScript := `require ["fileinto"];

# This script has a syntax error - missing semicolon
fileinto "Test"
`

	// Upload the INVALID Sieve script
	ctx := context.Background()
	_, _ = rdb.ExecWithRetry(ctx, "DELETE FROM sieve_scripts WHERE account_id = $1", accountID)
	_, err = rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
	`, accountID, "test-invalid", invalidSieveScript, true)
	if err != nil {
		t.Fatalf("Failed to insert Sieve script: %v", err)
	}

	// Create shared temp directory for both servers
	sharedTempDir := t.TempDir()
	s3Storage := &storage.S3Storage{}

	// Create shared uploader
	sharedUploader, err := uploader.New(
		context.Background(),
		sharedTempDir,
		10,
		2,
		3,
		5*time.Second,
		"test-shared-host",
		rdb,
		s3Storage,
		nil,
		make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create shared uploader: %v", err)
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
		sharedUploader,
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

	// Send message (use CRLF line endings)
	messageContent := strings.Join([]string{
		"From: sender@example.com",
		"To: " + account.Email,
		"Subject: Test Sieve Failure Resilience",
		"Date: " + time.Now().Format(time.RFC1123Z),
		"Message-ID: <test-sieve-failure-" + fmt.Sprintf("%d", time.Now().UnixNano()) + "@example.com>",
		"",
		"This message should be delivered even though the Sieve script is invalid.",
	}, "\r\n")

	if err := lmtpClient.SendCommand(messageContent + "\r\n."); err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Read per-recipient response
	dataResponses, err := lmtpClient.ReadDataResponses(1)
	if err != nil {
		t.Fatalf("Failed to read DATA responses: %v", err)
	}
	if !strings.HasPrefix(dataResponses[0], "250") {
		t.Fatalf("Expected 250 response after DATA (message should be accepted despite Sieve error), got: %s", dataResponses[0])
	}

	t.Logf("✓ Message accepted by LMTP despite invalid Sieve script")

	// Give system a moment to process
	time.Sleep(200 * time.Millisecond)

	// Setup IMAP server to verify message was delivered to INBOX
	imapAddr := common.GetRandomAddress(t)
	imapSrv, err := imapserver.New(
		context.Background(),
		"test-imap",
		"localhost",
		imapAddr,
		s3Storage,
		rdb,
		sharedUploader,
		nil,
		imapserver.IMAPServerOptions{InsecureAuth: true},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}
	defer imapSrv.Close()

	// Start IMAP server
	go func() {
		if err := imapSrv.Serve(imapAddr); err != nil {
			t.Logf("IMAP server error: %v", err)
		}
	}()

	// Give IMAP server a moment to start
	time.Sleep(200 * time.Millisecond)

	// Connect via IMAP
	c, err := imapclient.DialInsecure(imapAddr, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// Login
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("IMAP Login failed: %v", err)
	}

	// Select INBOX
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	// Verify there's 1 message (delivered despite Sieve failure)
	if selectData.NumMessages != 1 {
		t.Fatalf("Expected 1 message in INBOX (Sieve failure should not prevent delivery), got: %d", selectData.NumMessages)
	}

	t.Logf("✓ Message successfully delivered to INBOX despite Sieve script failure")
	t.Logf("✓ Sieve error handling test completed successfully")
}
