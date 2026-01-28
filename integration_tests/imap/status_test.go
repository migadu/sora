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

// TestIMAP_StatusDoesNotCorruptSelectedMailbox tests that STATUS on a different mailbox
// does not corrupt the internal message count of the currently selected mailbox
func TestIMAP_StatusDoesNotCorruptSelectedMailbox(t *testing.T) {
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

	// Step 1: Create a mailbox called "TestFolder" and add many messages to it
	if err := c.Create("TestFolder", nil).Wait(); err != nil {
		t.Fatalf("Failed to create TestFolder: %v", err)
	}

	// Add 100 messages to TestFolder to create a large message count
	for i := 0; i < 100; i++ {
		testMessage := fmt.Sprintf("From: test%d@example.com\r\n"+
			"To: %s\r\n"+
			"Subject: Test Message %d\r\n"+
			"Date: %s\r\n"+
			"\r\n"+
			"Test message body %d\r\n", i, account.Email, i, time.Now().Format(time.RFC1123), i)

		appendCmd := c.Append("TestFolder", int64(len(testMessage)), &imap.AppendOptions{
			Time: time.Now(),
		})
		if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
	}

	t.Log("Added 100 messages to TestFolder")

	// Step 2: Add 2 messages to INBOX
	for i := 0; i < 2; i++ {
		testMessage := fmt.Sprintf("From: inbox%d@example.com\r\n"+
			"To: %s\r\n"+
			"Subject: Inbox Message %d\r\n"+
			"Date: %s\r\n"+
			"\r\n"+
			"Inbox message body %d\r\n", i, account.Email, i, time.Now().Format(time.RFC1123), i)

		appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
			Time: time.Now(),
		})
		if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
			t.Fatalf("APPEND write to INBOX failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close for INBOX failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND to INBOX failed: %v", err)
		}
	}

	t.Log("Added 2 messages to INBOX")

	// Step 3: SELECT INBOX (should have 2 messages)
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Failed to SELECT INBOX: %v", err)
	}

	if selectData.NumMessages != 2 {
		t.Fatalf("Expected 2 messages in INBOX after SELECT, got %d", selectData.NumMessages)
	}

	t.Logf("SELECT INBOX: NumMessages=%d (expected 2)", selectData.NumMessages)

	// Step 4: Issue STATUS command for TestFolder (which has 100 messages)
	// This should NOT corrupt the internal message count for INBOX
	statusData, err := c.Status("TestFolder", &imap.StatusOptions{
		NumMessages: true,
	}).Wait()
	if err != nil {
		t.Fatalf("STATUS command for TestFolder failed: %v", err)
	}

	if statusData.NumMessages == nil || *statusData.NumMessages != 100 {
		t.Fatalf("Expected 100 messages in TestFolder, got %v", statusData.NumMessages)
	}

	t.Logf("STATUS TestFolder: NumMessages=%d (expected 100)", *statusData.NumMessages)

	// Step 5: Fetch messages from INBOX using sequence numbers
	// If the bug exists, the session will think INBOX has 100 messages (from the STATUS command),
	// but the database only has 2. The FETCH will try to fetch sequence numbers that don't exist.
	fetchOptions := &imap.FetchOptions{
		UID:      true,
		Envelope: true,
	}

	// Fetch messages 1:* (all messages in INBOX)
	// With the bug, this would try to fetch sequences 1-100 instead of 1-2
	fetchCmd := c.Fetch(imap.SeqSetNum(1, 2), fetchOptions)
	fetchMsgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH command failed: %v", err)
	}

	if len(fetchMsgs) != 2 {
		t.Errorf("Expected to FETCH 2 messages from INBOX, but got %d", len(fetchMsgs))
		t.Error("This indicates the STATUS command corrupted the selected mailbox's message count")
	} else {
		t.Log("FETCH correctly returned 2 messages - STATUS did not corrupt INBOX message count")
	}

	for i, msg := range fetchMsgs {
		t.Logf("FETCH returned message %d, UID=%d", i+1, msg.UID)
	}

	// Step 6: Issue NOOP to trigger a poll and verify the message count is still correct
	if err := c.Noop().Wait(); err != nil {
		t.Fatalf("NOOP command failed: %v", err)
	}

	// Step 7: Try to FETCH using sequence number 3 (which doesn't exist in INBOX with 2 messages)
	// This should return no results, not an error
	fetchCmd2 := c.Fetch(imap.SeqSetNum(3), fetchOptions)
	fetchMsgs2, err := fetchCmd2.Collect()
	if err != nil {
		t.Logf("FETCH sequence 3 completed (error is expected for out-of-range): %v", err)
	}

	if len(fetchMsgs2) > 0 {
		t.Errorf("FETCH of non-existent sequence number 3 returned %d messages (UID=%d)", len(fetchMsgs2), fetchMsgs2[0].UID)
		t.Error("This indicates the session thinks there are more than 2 messages in INBOX")
	} else {
		t.Log("FETCH of sequence 3 correctly returned no results")
	}

	t.Log("STATUS does not corrupt selected mailbox test completed successfully")
}
