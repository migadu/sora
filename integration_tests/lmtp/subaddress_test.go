//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestLMTP_SubaddressEnvelope tests that the Sieve envelope contains the +detail
// when using subaddress extension with "envelope :matches :detail"
func TestLMTP_SubaddressEnvelope(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	ctx := context.Background()

	// Setup database and account
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Create shared temp directory for LMTP server
	sharedTempDir := t.TempDir()

	// Create shared S3 storage (empty for testing)
	s3Storage := &storage.S3Storage{}

	// Get account ID
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	// Create Sieve script that uses envelope :detail to file into folders
	sieveScript := `
require "fileinto";
require "envelope";
require "mailbox";
require "subaddress";
require "variables";

if envelope :matches :detail "To" "*" {
  set :lower "detail" "${1}";
  fileinto :create "${detail}";
}
`

	// Store Sieve script for the account
	_, err = rdb.ExecWithRetry(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active)
		VALUES ($1, $2, $3, $4)
	`, accountID, "subaddress-test", sieveScript, true)
	if err != nil {
		t.Fatalf("Failed to create Sieve script: %v", err)
	}

	// Create shared uploader
	sharedUploader, err := uploader.New(
		ctx,
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

	// Setup LMTP server
	lmtpAddr := common.GetRandomAddress(t)
	lmtpSrv, err := lmtpserver.New(
		ctx,
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

	// Test multiple subaddresses
	testCases := []struct {
		detail          string
		expectedMailbox string
	}{
		{"work", "work"},
		{"Personal", "personal"}, // Should be lowercased by script
		{"Shopping", "shopping"},
	}

	for _, tc := range testCases {
		t.Run(tc.detail, func(t *testing.T) {
			// Split email to insert +detail before @
			parts := strings.Split(account.Email, "@")
			if len(parts) != 2 {
				t.Fatalf("Invalid email format: %s", account.Email)
			}
			recipientWithDetail := fmt.Sprintf("%s+%s@%s", parts[0], tc.detail, parts[1])

			messageContent := strings.Join([]string{
				"From: sender@example.com",
				fmt.Sprintf("To: %s", recipientWithDetail),
				"Subject: Test subaddress",
				"Date: " + time.Now().Format(time.RFC1123Z),
				fmt.Sprintf("Message-ID: <test-subaddress-%d@example.com>", time.Now().UnixNano()),
				"",
				fmt.Sprintf("Test message for +%s detail", tc.detail),
			}, "\r\n")

			// Use LMTPClient helper
			lmtpClient, err := NewLMTPClient(lmtpAddr)
			if err != nil {
				t.Fatalf("Failed to connect to LMTP: %v", err)
			}
			defer lmtpClient.Close()

			// Send LHLO
			if err := lmtpClient.SendCommand("LHLO test-client"); err != nil {
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

			// Send RCPT TO with +detail
			if err := lmtpClient.SendCommand(fmt.Sprintf("RCPT TO:<%s>", recipientWithDetail)); err != nil {
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

			// Send message content
			if err := lmtpClient.SendCommand(messageContent + "\r\n."); err != nil {
				t.Fatalf("Failed to send message: %v", err)
			}
			dataResponse, err := lmtpClient.ReadResponse()
			if err != nil {
				t.Fatalf("Failed to read message response: %v", err)
			}
			if !strings.HasPrefix(dataResponse, "250") {
				t.Fatalf("Expected 250 response after DATA, got: %s", dataResponse)
			}

			t.Logf("✓ Message delivered to %s", recipientWithDetail)

			// Verify mailbox was created
			var mailboxExists bool
			err = rdb.QueryRowWithRetry(ctx, `
				SELECT EXISTS(
					SELECT 1 FROM mailboxes
					WHERE account_id = $1 AND name = $2
				)
			`, accountID, tc.expectedMailbox).Scan(&mailboxExists)
			if err != nil {
				t.Fatalf("Failed to check mailbox: %v", err)
			}
			if !mailboxExists {
				t.Fatalf("Mailbox '%s' was not created by Sieve :create", tc.expectedMailbox)
			}
			t.Logf("✓ Mailbox '%s' was created", tc.expectedMailbox)
		})
	}

	// Now verify messages are in correct mailboxes by checking database
	for _, tc := range testCases {
		t.Run("verify_"+tc.detail, func(t *testing.T) {
			// Check message count in the mailbox
			var msgCount int
			err := rdb.QueryRowWithRetry(ctx, `
				SELECT COUNT(*)
				FROM messages m
				JOIN mailboxes mb ON m.mailbox_id = mb.id
				WHERE mb.account_id = $1 AND mb.name = $2
			`, accountID, tc.expectedMailbox).Scan(&msgCount)
			if err != nil {
				t.Fatalf("Failed to query messages in '%s': %v", tc.expectedMailbox, err)
			}

			if msgCount != 1 {
				t.Fatalf("Expected 1 message in '%s', got %d", tc.expectedMailbox, msgCount)
			}

			t.Logf("✓ Message correctly delivered to mailbox '%s'", tc.expectedMailbox)
		})
	}

	// Verify INBOX is empty (all messages went to +detail folders)
	var inboxCount int
	err = rdb.QueryRowWithRetry(ctx, `
		SELECT COUNT(*)
		FROM messages m
		JOIN mailboxes mb ON m.mailbox_id = mb.id
		WHERE mb.account_id = $1 AND mb.name = 'INBOX'
	`, accountID).Scan(&inboxCount)
	if err != nil {
		t.Fatalf("Failed to query INBOX messages: %v", err)
	}
	if inboxCount != 0 {
		t.Fatalf("Expected INBOX to be empty, got %d messages", inboxCount)
	}

	t.Log("✓ INBOX is empty (all messages routed by subaddress)")
	t.Log("✓ Subaddress envelope test completed successfully")
}
