//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	imapServer "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestIMAP_ComprehensiveMailboxStatus tests comprehensive STATUS operations
func TestIMAP_ComprehensiveMailboxStatus(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Test 1: STATUS on empty INBOX
	statusData, err := c.Status("INBOX", &imap.StatusOptions{
		NumMessages:   true,
		NumUnseen:     true,
		UIDNext:       true,
		UIDValidity:   true,
		HighestModSeq: true,
	}).Wait()
	if err != nil {
		t.Fatalf("STATUS command failed: %v", err)
	}

	if statusData.Mailbox != "INBOX" {
		t.Errorf("Expected mailbox INBOX, got %s", statusData.Mailbox)
	}

	if statusData.NumMessages != nil && *statusData.NumMessages != 0 {
		t.Errorf("Expected 0 messages in empty INBOX, got %d", *statusData.NumMessages)
	}

	if statusData.NumUnseen != nil && *statusData.NumUnseen != 0 {
		t.Errorf("Expected 0 unseen messages in empty INBOX, got %d", *statusData.NumUnseen)
	}

	t.Logf("Empty INBOX status - Messages: %v, Unseen: %v, UIDNext: %d, UIDValidity: %d, HighestModSeq: %d",
		statusData.NumMessages, statusData.NumUnseen, statusData.UIDNext, statusData.UIDValidity, statusData.HighestModSeq)

	// Add some messages to test with
	testMessage1 := "From: test1@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Status Test Message 1\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"First test message for status testing.\r\n"

	testMessage2 := "From: test2@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Status Test Message 2\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"Second test message for status testing.\r\n"

	// Append first message with \Seen flag
	appendCmd1 := c.Append("INBOX", int64(len(testMessage1)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen},
		Time:  time.Now(),
	})
	_, err = appendCmd1.Write([]byte(testMessage1))
	if err != nil {
		t.Fatalf("APPEND write first message failed: %v", err)
	}
	err = appendCmd1.Close()
	if err != nil {
		t.Fatalf("APPEND close first message failed: %v", err)
	}
	_, err = appendCmd1.Wait()
	if err != nil {
		t.Fatalf("APPEND first message failed: %v", err)
	}

	// Append second message without \Seen flag (unseen)
	appendCmd2 := c.Append("INBOX", int64(len(testMessage2)), &imap.AppendOptions{
		Flags: []imap.Flag{},
		Time:  time.Now(),
	})
	_, err = appendCmd2.Write([]byte(testMessage2))
	if err != nil {
		t.Fatalf("APPEND write second message failed: %v", err)
	}
	err = appendCmd2.Close()
	if err != nil {
		t.Fatalf("APPEND close second message failed: %v", err)
	}
	_, err = appendCmd2.Wait()
	if err != nil {
		t.Fatalf("APPEND second message failed: %v", err)
	}

	// Test 2: STATUS after adding messages
	statusData, err = c.Status("INBOX", &imap.StatusOptions{
		NumMessages:   true,
		NumUnseen:     true,
		UIDNext:       true,
		UIDValidity:   true,
		HighestModSeq: true,
	}).Wait()
	if err != nil {
		t.Fatalf("STATUS command after adding messages failed: %v", err)
	}

	if statusData.NumMessages != nil && *statusData.NumMessages != 2 {
		t.Errorf("Expected 2 messages after adding, got %d", *statusData.NumMessages)
	}

	if statusData.NumUnseen != nil && *statusData.NumUnseen != 1 {
		t.Errorf("Expected 1 unseen message after adding, got %d", *statusData.NumUnseen)
	}

	t.Logf("INBOX status after adding messages - Messages: %d, Unseen: %d, UIDNext: %d, UIDValidity: %d, HighestModSeq: %d",
		statusData.NumMessages, statusData.NumUnseen, statusData.UIDNext, statusData.UIDValidity, statusData.HighestModSeq)

	// Test 3: STATUS with selective options
	statusData, err = c.Status("INBOX", &imap.StatusOptions{
		NumMessages: true,
		UIDNext:     true,
	}).Wait()
	if err != nil {
		t.Fatalf("STATUS with selective options failed: %v", err)
	}

	// Only requested fields should be populated
	if statusData.NumMessages == nil {
		t.Error("NumMessages should be populated when requested")
	}
	if statusData.UIDNext == 0 {
		t.Error("UIDNext should be populated when requested")
	}
	t.Logf("Selective STATUS - Messages: %v, UIDNext: %d", statusData.NumMessages, statusData.UIDNext)

	// Test 4: STATUS on non-existent mailbox (should fail)
	_, err = c.Status("NonExistentMailbox", &imap.StatusOptions{
		NumMessages: true,
	}).Wait()
	if err == nil {
		t.Error("STATUS on non-existent mailbox should fail")
	} else {
		t.Logf("STATUS correctly failed on non-existent mailbox: %v", err)
	}

	t.Log("Comprehensive mailbox status test completed successfully")
}

// TestIMAP_StatusAppendLimit tests that STATUS correctly returns APPENDLIMIT
func TestIMAP_StatusAppendLimit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Create custom server with specific AppendLimit
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := common.GetRandomAddress(t)

	// Create a temporary directory for the uploader
	tempDir, err := os.MkdirTemp("", "sora-test-upload-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create error channel for uploader
	errCh := make(chan error, 1)

	// Create UploadWorker for testing
	uploadWorker, err := uploader.New(
		context.Background(),
		tempDir,              // path
		10,                   // batchSize
		1,                    // concurrency
		3,                    // maxAttempts
		time.Second,          // retryInterval
		"test-instance",      // instanceID
		rdb,                  // database
		&storage.S3Storage{}, // S3 storage
		nil,                  // cache (can be nil)
		errCh,                // error channel
	)
	if err != nil {
		t.Fatalf("Failed to create upload worker: %v", err)
	}

	// Set AppendLimit to 25MB (same as config.toml)
	const expectedAppendLimit = 25 * 1024 * 1024 // 25MB in bytes

	server, err := imapServer.New(
		context.Background(),
		"test",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		uploadWorker,
		nil, // cache.Cache
		imapServer.IMAPServerOptions{
			AppendLimit: expectedAppendLimit,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create IMAP server: %v", err)
	}

	// Start server in background
	errChan := make(chan error, 1)
	go func() {
		if err := server.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			errChan <- fmt.Errorf("IMAP server error: %w", err)
		}
	}()

	// Set up cleanup function
	cleanup := func() {
		server.Close()
		select {
		case err := <-errChan:
			if err != nil {
				t.Logf("IMAP server error during shutdown: %v", err)
			}
		case <-time.After(1 * time.Second):
			// Timeout waiting for server to shut down
		}
		os.RemoveAll(tempDir)
	}
	defer cleanup()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	c, err := imapclient.DialInsecure(address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Test 1: STATUS with AppendLimit option
	statusData, err := c.Status("INBOX", &imap.StatusOptions{
		AppendLimit: true,
	}).Wait()
	if err != nil {
		t.Fatalf("STATUS command with AppendLimit failed: %v", err)
	}

	if statusData.Mailbox != "INBOX" {
		t.Errorf("Expected mailbox INBOX, got %s", statusData.Mailbox)
	}

	if statusData.AppendLimit == nil {
		t.Fatal("AppendLimit should be populated when requested")
	}

	if *statusData.AppendLimit != expectedAppendLimit {
		t.Errorf("Expected AppendLimit %d, got %d", expectedAppendLimit, *statusData.AppendLimit)
	}

	t.Logf("STATUS AppendLimit test passed - configured: %d bytes (25MB), returned: %d bytes",
		expectedAppendLimit, *statusData.AppendLimit)

	// Test 2: STATUS with mixed options including AppendLimit
	statusData, err = c.Status("INBOX", &imap.StatusOptions{
		NumMessages: true,
		AppendLimit: true,
		UIDNext:     true,
	}).Wait()
	if err != nil {
		t.Fatalf("STATUS command with mixed options failed: %v", err)
	}

	if statusData.AppendLimit == nil {
		t.Fatal("AppendLimit should be populated when requested in mixed options")
	}

	if *statusData.AppendLimit != expectedAppendLimit {
		t.Errorf("Expected AppendLimit %d in mixed options, got %d", expectedAppendLimit, *statusData.AppendLimit)
	}

	if statusData.NumMessages == nil {
		t.Error("NumMessages should be populated when requested")
	}

	if statusData.UIDNext == 0 {
		t.Error("UIDNext should be populated when requested")
	}

	t.Logf("Mixed STATUS options test passed - AppendLimit: %d, NumMessages: %v, UIDNext: %d",
		*statusData.AppendLimit, statusData.NumMessages, statusData.UIDNext)

	t.Log("STATUS APPENDLIMIT integration test completed successfully")
}
