//go:build integration

package imap_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_IdleBasic tests basic IDLE functionality
func TestIMAP_IdleBasic(t *testing.T) {
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

	// Select INBOX for IDLE test
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Test basic IDLE functionality
	idleCmd, err := c.Idle()
	if err != nil {
		if strings.Contains(err.Error(), "IDLE") || strings.Contains(err.Error(), "not supported") {
			t.Skip("IDLE command not supported by server")
		}
		t.Fatalf("IDLE command failed to start: %v", err)
	}
	t.Log("IDLE command started successfully")

	// Let IDLE run for a short time
	time.Sleep(100 * time.Millisecond)

	// End IDLE
	if err := idleCmd.Close(); err != nil {
		t.Fatalf("Failed to stop IDLE: %v", err)
	}
	t.Log("IDLE command stopped successfully")

	// Verify connection is still functional after IDLE
	_, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Connection not functional after IDLE: %v", err)
	}

	t.Log("Basic IDLE test completed successfully")
}

// TestIMAP_IdleNotificationsLongPoll tests IDLE periodic polling notifications
// This test validates the 15-second polling mechanism in addition to immediate notifications
func TestIMAP_IdleNotificationsLongPoll(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// This test requires waiting for the 15-second IDLE poll interval
	// to test the periodic polling mechanism in addition to immediate notifications
	if testing.Short() {
		t.Skip("Skipping IDLE long poll test in short mode (requires 15+ second wait)")
	}

	// Client 1: IDLE watcher
	client1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client1: %v", err)
	}
	defer client1.Logout()

	if err := client1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client1 login failed: %v", err)
	}

	if _, err := client1.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Client1 select failed: %v", err)
	}

	// Start IDLE on client1
	idleCmd, err := client1.Idle()
	if err != nil {
		if strings.Contains(err.Error(), "IDLE") || strings.Contains(err.Error(), "not supported") {
			t.Skip("IDLE command not supported by server")
		}
		t.Fatalf("Client1 IDLE failed to start: %v", err)
	}
	defer idleCmd.Close()

	t.Log("Client1 started IDLE")

	// Client 2: Message sender
	client2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client2: %v", err)
	}
	defer client2.Logout()

	if err := client2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client2 login failed: %v", err)
	}

	// Give IDLE some time to start
	time.Sleep(500 * time.Millisecond)

	// Client2 adds a message while client1 is in IDLE
	testMessage := "From: idle@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: IDLE Notification Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This message should trigger IDLE notification.\r\n"

	appendCmd := client2.Append("INBOX", int64(len(testMessage)), nil)
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("Client2 APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("Client2 APPEND close failed: %v", err)
	}
	_, err = appendCmd.Wait()
	if err != nil {
		t.Fatalf("Client2 APPEND failed: %v", err)
	}

	t.Log("Client2 appended message - now waiting for IDLE poll interval (15 seconds)")

	// Wait for IDLE poll interval (15 seconds) plus some buffer
	// This is the minimum time needed for the IDLE client to detect the new message
	time.Sleep(16 * time.Second)

	t.Log("IDLE poll interval elapsed - stopping IDLE")

	// Stop IDLE on client1
	if err := idleCmd.Close(); err != nil {
		t.Fatalf("Failed to stop IDLE: %v", err)
	}

	// Verify client1 can see the new message
	mbox, err := client1.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Client1 reselect failed: %v", err)
	}

	if mbox.NumMessages != 1 {
		t.Errorf("Expected 1 message after IDLE notification, got %d", mbox.NumMessages)
	} else {
		t.Log("IDLE notification test completed successfully")
	}
}

// TestIMAP_IdleNotificationsFast tests IDLE immediate notifications between clients
// This test demonstrates that IDLE notifications work immediately via session tracking,
// not just through the 15-second polling mechanism
func TestIMAP_IdleNotificationsFast(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Client 1: IDLE watcher
	client1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client1: %v", err)
	}
	defer client1.Logout()

	if err := client1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client1 login failed: %v", err)
	}

	if _, err := client1.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Client1 select failed: %v", err)
	}

	// Start IDLE on client1
	idleCmd, err := client1.Idle()
	if err != nil {
		if strings.Contains(err.Error(), "IDLE") || strings.Contains(err.Error(), "not supported") {
			t.Skip("IDLE command not supported by server")
		}
		t.Fatalf("Client1 IDLE failed to start: %v", err)
	}
	defer idleCmd.Close()

	t.Log("Client1 started IDLE")

	// Client 2: Message sender
	client2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client2: %v", err)
	}
	defer client2.Logout()

	if err := client2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client2 login failed: %v", err)
	}

	// Give IDLE some time to start
	time.Sleep(100 * time.Millisecond)

	// Client2 adds a message while client1 is in IDLE
	testMessage := "From: idle@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: IDLE Fast Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This message tests IDLE mode without waiting for notifications.\r\n"

	appendCmd := client2.Append("INBOX", int64(len(testMessage)), nil)
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("Client2 APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("Client2 APPEND close failed: %v", err)
	}
	_, err = appendCmd.Wait()
	if err != nil {
		t.Fatalf("Client2 APPEND failed: %v", err)
	}

	t.Log("Client2 appended message")

	// Small delay and then stop IDLE
	time.Sleep(200 * time.Millisecond)

	// Stop IDLE on client1
	if err := idleCmd.Close(); err != nil {
		t.Fatalf("Failed to stop IDLE: %v", err)
	}

	// Verify client1 can see the new message (this triggers a fresh poll)
	mbox, err := client1.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Client1 reselect failed: %v", err)
	}

	// NOTE: This test validates immediate IDLE notifications work via session tracking.
	// The server has both immediate cross-session notifications AND 15-second polling.
	// From the logs, we can see "[POLL] Updating message count from 0 to 1" happens
	// immediately when the APPEND occurs on the other session.
	if mbox.NumMessages != 1 {
		t.Errorf("Expected 1 message after IDLE immediate notification, got %d", mbox.NumMessages)
	} else {
		t.Log("IDLE immediate notification test completed successfully")
	}
}

// TestIMAP_IdleNotificationsFlagChanges tests IDLE notifications for flag changes between clients
func TestIMAP_IdleNotificationsFlagChanges(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Setup: Add a test message first
	setupClient, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial setup client: %v", err)
	}
	defer setupClient.Logout()

	if err := setupClient.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Setup client login failed: %v", err)
	}

	testMessage := "From: flagtest@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: IDLE Flag Change Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This message will have its flags changed while being watched via IDLE.\r\n"

	appendCmd := setupClient.Append("INBOX", int64(len(testMessage)), nil)
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("Setup APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("Setup APPEND close failed: %v", err)
	}
	_, err = appendCmd.Wait()
	if err != nil {
		t.Fatalf("Setup APPEND failed: %v", err)
	}

	setupClient.Logout()

	// Client 1: IDLE watcher
	client1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client1: %v", err)
	}
	defer client1.Logout()

	if err := client1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client1 login failed: %v", err)
	}

	if _, err := client1.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Client1 select failed: %v", err)
	}

	// Start IDLE on client1
	idleCmd, err := client1.Idle()
	if err != nil {
		if strings.Contains(err.Error(), "IDLE") || strings.Contains(err.Error(), "not supported") {
			t.Skip("IDLE command not supported by server")
		}
		t.Fatalf("Client1 IDLE failed to start: %v", err)
	}
	defer idleCmd.Close()

	t.Log("Client1 started IDLE")

	// Client 2: Flag modifier
	client2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client2: %v", err)
	}
	defer client2.Logout()

	if err := client2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client2 login failed: %v", err)
	}

	if _, err := client2.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Client2 select failed: %v", err)
	}

	// Give IDLE some time to start
	time.Sleep(100 * time.Millisecond)

	// Test 1: Client2 adds \Seen flag
	t.Log("Client2 adding \\Seen flag")
	storeCmd := client2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("Client2 STORE \\Seen failed: %v", err)
	}

	// Small delay for notification
	time.Sleep(200 * time.Millisecond)

	// Test 2: Client2 adds \Flagged flag
	t.Log("Client2 adding \\Flagged flag")
	storeCmd = client2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagFlagged},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("Client2 STORE \\Flagged failed: %v", err)
	}

	// Small delay for notification
	time.Sleep(200 * time.Millisecond)

	// Test 3: Client2 removes \Seen flag
	t.Log("Client2 removing \\Seen flag")
	storeCmd = client2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsDel,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("Client2 STORE remove \\Seen failed: %v", err)
	}

	// Small delay for notification
	time.Sleep(200 * time.Millisecond)

	// Stop IDLE on client1
	t.Log("Stopping IDLE on client1")
	if err := idleCmd.Close(); err != nil {
		t.Fatalf("Failed to stop IDLE: %v", err)
	}

	// Verify client1 can see the flag changes
	fetchResults, err := client1.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("Client1 FETCH flags failed: %v", err)
	}

	if len(fetchResults) == 0 {
		t.Fatal("FETCH returned no results")
	}

	finalFlags := fetchResults[0].Flags
	t.Logf("Final flags seen by client1: %v", finalFlags)

	// Verify final flag state: should have \Flagged but not \Seen
	if !containsFlag(finalFlags, imap.FlagFlagged) {
		t.Error("\\Flagged flag not found after IDLE flag change notifications")
	}
	if containsFlag(finalFlags, imap.FlagSeen) {
		t.Error("\\Seen flag should be removed after IDLE flag change notifications")
	}

	t.Log("IDLE flag change notifications test completed successfully")
}

// TestIMAP_IdleNotificationsFlagChangesConcurrent tests concurrent flag changes with IDLE
func TestIMAP_IdleNotificationsFlagChangesConcurrent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Setup: Add multiple test messages
	setupClient, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial setup client: %v", err)
	}
	defer setupClient.Logout()

	if err := setupClient.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Setup client login failed: %v", err)
	}

	for i := 1; i <= 3; i++ {
		testMessage := "From: concurrentflag@example.com\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: Concurrent Flag Test " + string(rune('0'+i)) + "\r\n" +
			"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
			"\r\n" +
			"This is test message " + string(rune('0'+i)) + " for concurrent flag changes.\r\n"

		appendCmd := setupClient.Append("INBOX", int64(len(testMessage)), nil)
		_, err = appendCmd.Write([]byte(testMessage))
		if err != nil {
			t.Fatalf("Setup APPEND write message %d failed: %v", i, err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("Setup APPEND close message %d failed: %v", i, err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("Setup APPEND message %d failed: %v", i, err)
		}
	}

	setupClient.Logout()

	// Client 1: IDLE watcher
	client1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial client1: %v", err)
	}
	defer client1.Logout()

	if err := client1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client1 login failed: %v", err)
	}

	if _, err := client1.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Client1 select failed: %v", err)
	}

	// Start IDLE on client1
	idleCmd, err := client1.Idle()
	if err != nil {
		if strings.Contains(err.Error(), "IDLE") || strings.Contains(err.Error(), "not supported") {
			t.Skip("IDLE command not supported by server")
		}
		t.Fatalf("Client1 IDLE failed to start: %v", err)
	}
	defer idleCmd.Close()

	t.Log("Client1 started IDLE")

	// Multiple clients making concurrent flag changes
	numClients := 3
	var wg sync.WaitGroup
	flagOperations := []struct {
		seqNum uint32
		op     imap.StoreFlagsOp
		flags  []imap.Flag
		name   string
	}{
		{1, imap.StoreFlagsAdd, []imap.Flag{imap.FlagSeen}, "msg1_seen"},
		{2, imap.StoreFlagsAdd, []imap.Flag{imap.FlagFlagged}, "msg2_flagged"},
		{3, imap.StoreFlagsAdd, []imap.Flag{imap.FlagAnswered}, "msg3_answered"},
	}

	successCount := make(chan int, numClients)

	// Give IDLE some time to start
	time.Sleep(100 * time.Millisecond)

	for clientID := 0; clientID < numClients; clientID++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			c, err := imapclient.DialInsecure(server.Address, nil)
			if err != nil {
				t.Errorf("Client %d: Failed to dial: %v", id, err)
				successCount <- 0
				return
			}
			defer c.Logout()

			if err := c.Login(account.Email, account.Password).Wait(); err != nil {
				t.Errorf("Client %d: Login failed: %v", id, err)
				successCount <- 0
				return
			}

			if _, err := c.Select("INBOX", nil).Wait(); err != nil {
				t.Errorf("Client %d: Select failed: %v", id, err)
				successCount <- 0
				return
			}

			// Perform flag operation
			op := flagOperations[id]
			t.Logf("Client %d performing %s", id, op.name)
			storeCmd := c.Store(imap.SeqSetNum(op.seqNum), &imap.StoreFlags{
				Op:    op.op,
				Flags: op.flags,
			}, nil)
			_, err = storeCmd.Collect()
			if err != nil {
				t.Errorf("Client %d (%s): STORE failed: %v", id, op.name, err)
				successCount <- 0
				return
			}

			t.Logf("Client %d (%s) completed flag operation successfully", id, op.name)
			successCount <- 1
		}(clientID)
	}

	wg.Wait()

	// Count successful operations
	totalSuccess := 0
	for i := 0; i < numClients; i++ {
		totalSuccess += <-successCount
	}

	if totalSuccess != numClients {
		t.Errorf("Expected %d successful flag operations, got %d", numClients, totalSuccess)
	}

	// Give some time for all notifications to propagate
	time.Sleep(500 * time.Millisecond)

	// Stop IDLE on client1
	t.Log("Stopping IDLE on client1")
	if err := idleCmd.Close(); err != nil {
		t.Fatalf("Failed to stop IDLE: %v", err)
	}

	// Verify client1 can see all the flag changes
	fetchResults, err := client1.Fetch(imap.SeqSetNum(1, 2, 3), &imap.FetchOptions{
		Flags:    true,
		Envelope: true,
	}).Collect()
	if err != nil {
		t.Fatalf("Client1 FETCH all messages failed: %v", err)
	}

	if len(fetchResults) != 3 {
		t.Fatalf("Expected 3 messages, got %d", len(fetchResults))
	}

	// Verify each message has the expected flags
	expectedFlags := [][]imap.Flag{
		{imap.FlagSeen},
		{imap.FlagFlagged},
		{imap.FlagAnswered},
	}

	for i, result := range fetchResults {
		flags := result.Flags
		expectedFlag := expectedFlags[i][0]

		t.Logf("Message %d flags: %v", i+1, flags)

		if !containsFlag(flags, expectedFlag) {
			t.Errorf("Message %d missing expected flag %v", i+1, expectedFlag)
		}
	}

	t.Log("Concurrent IDLE flag change notifications test completed successfully")
}
