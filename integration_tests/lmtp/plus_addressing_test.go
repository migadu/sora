//go:build integration

package lmtp_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	imapserver "github.com/migadu/sora/server/imap"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"

	"github.com/migadu/sora/integration_tests/common"
)

// TestLMTP_PlusAddressingWithSharedUploader tests that messages delivered to plus addresses
// (e.g., user+alias@domain.com) are stored correctly and can be retrieved via IMAP.
// This test catches the S3 key mismatch bug where s3_localpart was stored with the full
// alias instead of the base address.
//
// This test uses a SHARED uploader temp directory for both LMTP and IMAP servers,
// allowing IMAP to retrieve messages delivered via LMTP from local storage.
func TestLMTP_PlusAddressingWithSharedUploader(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup database and account
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Create SHARED temp directory for both servers
	sharedTempDir := t.TempDir()
	t.Logf("Using shared upload directory: %s", sharedTempDir)

	// Create shared S3 storage (empty for testing)
	s3Storage := &storage.S3Storage{}

	// Create SHARED uploader that both servers will use
	sharedUploader, err := uploader.New(
		context.Background(),
		sharedTempDir,
		10,            // batch size
		2,             // concurrency
		3,             // max attempts
		5*time.Second, // retry interval
		"test-shared-host",
		rdb,
		s3Storage,
		nil, // cache
		make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create shared uploader: %v", err)
	}

	// Setup LMTP server with shared uploader
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

	// Setup IMAP server with SAME shared uploader
	imapAddr := common.GetRandomAddress(t)
	imapSrv, err := imapserver.New(
		context.Background(),
		"test-imap",
		"localhost",
		imapAddr,
		s3Storage,
		rdb,
		sharedUploader,
		nil, // cache
		imapserver.IMAPServerOptions{},
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

	// Give servers a moment to start listening
	time.Sleep(200 * time.Millisecond)

	// Test delivering to plus address
	baseEmail := account.Email
	plusAddress := strings.Replace(baseEmail, "@", "+alias@", 1)

	t.Logf("Base account email: %s", baseEmail)
	t.Logf("Plus address for delivery: %s", plusAddress)

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

	// Send RCPT TO with plus address
	t.Logf("Delivering to plus address: %s", plusAddress)
	if err := lmtpClient.SendCommand(fmt.Sprintf("RCPT TO:<%s>", plusAddress)); err != nil {
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

	// Send message
	messageContent := fmt.Sprintf(`From: sender@example.com
To: %s
Subject: Test Plus Addressing
Date: %s
Message-ID: <test-plus-lmtp-%d@example.com>

This is a test message to verify plus addressing S3 key handling.
The message should be stored with the base address in s3_localpart,
not the full plus address.
`, plusAddress, time.Now().Format(time.RFC1123Z), time.Now().UnixNano())

	if err := lmtpClient.SendCommand(messageContent + "\r\n."); err != nil {
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

	t.Logf("✓ Message delivered to plus address via LMTP")

	// Give system a moment to process
	time.Sleep(200 * time.Millisecond)

	// Now FETCH the message via IMAP
	// Since both servers share the same uploader temp directory,
	// IMAP can retrieve the locally-stored message
	c, err := imapclient.DialInsecure(imapAddr, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	// Login with base address
	if err := c.Login(baseEmail, account.Password).Wait(); err != nil {
		t.Fatalf("IMAP Login failed: %v", err)
	}

	// Select INBOX
	_, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	// Fetch the message body
	fetchCmd := c.Fetch(imap.UIDSetNum(1), &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{
			{Part: []int{}}, // BODY[] (full message)
		},
	})

	var messageBody []byte
	for {
		msg := fetchCmd.Next()
		if msg == nil {
			break
		}
		for {
			item := msg.Next()
			if item == nil {
				break
			}
			if bodyItem, ok := item.(imapclient.FetchItemDataBodySection); ok {
				buf := new(bytes.Buffer)
				if _, err := io.Copy(buf, bodyItem.Literal); err != nil {
					t.Fatalf("Failed to read message body: %v", err)
				}
				messageBody = buf.Bytes()
			}
		}
	}

	if err := fetchCmd.Close(); err != nil {
		t.Fatalf("FETCH command failed: %v", err)
	}

	// Verify we got a non-empty body
	if len(messageBody) == 0 {
		// Check if file exists in shared directory for debugging
		files, _ := os.ReadDir(sharedTempDir)
		t.Logf("Files in shared temp dir: %v", files)

		t.Fatalf("FETCH returned empty body (size=0) - this indicates S3 key mismatch bug!\n"+
			"Message was delivered to %s but s3_localpart was likely stored with the full alias.\n"+
			"Expected s3_localpart='%s' (base address), got wrong value.",
			plusAddress,
			strings.Split(baseEmail, "@")[0])
	}

	// Verify content
	if !strings.Contains(string(messageBody), "Test Plus Addressing") {
		t.Fatalf("Retrieved body doesn't contain expected content. Got %d bytes", len(messageBody))
	}

	t.Logf("✓ Successfully retrieved message body via IMAP (%d bytes)", len(messageBody))
	t.Logf("✓ S3 key is constructed correctly (using base address localpart)")
	t.Logf("✓ Plus addressing with LMTP → IMAP test completed successfully")
}
