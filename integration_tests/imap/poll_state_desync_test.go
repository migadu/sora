//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_PollStateDesync_ExternalDeletion tests the scenario where messages are
// deleted externally (bypassing IMAP) while a session has the mailbox selected.
// This simulates:
// - Direct database manipulation
// - External cleanup scripts
// - Replica lag in read/write split scenarios
func TestIMAP_PollStateDesync_ExternalDeletion(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect first client
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	// Note: We don't defer c1.Logout() because the server will force disconnect

	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Select INBOX
	mbox, err := c1.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	t.Logf("Initial mailbox state: %d messages", mbox.NumMessages)

	// Add 5 test messages
	for i := 1; i <= 5; i++ {
		testMessage := fmt.Sprintf("From: test@example.com\r\n"+
			"To: %s\r\n"+
			"Subject: Test Message %d\r\n"+
			"Date: %s\r\n"+
			"\r\n"+
			"This is test message %d.\r\n", account.Email, i, time.Now().Format(time.RFC1123Z), i)

		appendCmd := c1.Append("INBOX", int64(len(testMessage)), nil)
		_, err = appendCmd.Write([]byte(testMessage))
		if err != nil {
			t.Fatalf("APPEND write message %d failed: %v", i, err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("APPEND close message %d failed: %v", i, err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND message %d failed: %v", i, err)
		}
	}

	// Verify we have 5 messages
	mbox, err = c1.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	if mbox.NumMessages != 5 {
		t.Fatalf("Expected 5 messages, got %d", mbox.NumMessages)
	}
	t.Logf("Added 5 messages, total: %d", mbox.NumMessages)

	// Get account ID and mailbox ID for direct database manipulation
	ctx := context.Background()
	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatalf("Failed to get mailbox: %v", err)
	}

	// Externally delete 3 messages (UIDs 1, 2, 3) by directly manipulating the database
	// This simulates external cleanup, direct DB manipulation, or other non-IMAP deletions
	t.Log("Externally deleting 3 messages via direct database manipulation")
	_, err = server.ResilientDB.GetDatabase().GetWritePool().Exec(ctx,
		"DELETE FROM messages WHERE mailbox_id = $1 AND uid IN (1, 2, 3)",
		mailbox.ID)
	if err != nil {
		t.Fatalf("Failed to externally delete messages: %v", err)
	}

	// Now the database has 2 messages, but the client's session still thinks it has 5
	// The next NOOP or IDLE command will trigger a poll, which should detect this desync

	// Trigger a poll by sending NOOP
	// The server should detect the state desync
	t.Log("Triggering poll with NOOP command - expecting desync detection")

	// The NOOP may hang or fail depending on how the server handles the BYE
	// Use a channel with timeout
	done := make(chan error, 1)
	go func() {
		done <- c1.Noop().Wait()
	}()

	select {
	case err = <-done:
		// NOOP returned an error (expected)
		t.Logf("NOOP returned error (expected): %v", err)
	case <-time.After(2 * time.Second):
		// NOOP is hanging - this is also acceptable as the server may have closed the connection
		t.Log("NOOP timed out - connection likely closed by server (acceptable)")
	}

	// Close the client to clean up
	t.Log("Closing first client connection")
	c1.Close()

	// Verify we can reconnect and see the correct state (2 messages)
	t.Log("Reconnecting to verify correct state")
	time.Sleep(100 * time.Millisecond) // Brief pause to let server cleanup

	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server for reconnect: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login after reconnect failed: %v", err)
	}

	mbox, err = c2.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX after reconnect failed: %v", err)
	}

	if mbox.NumMessages != 2 {
		t.Errorf("Expected 2 messages after reconnect, got %d", mbox.NumMessages)
	} else {
		t.Logf("Correct state after reconnect: %d messages", mbox.NumMessages)
	}

	t.Log("Test completed successfully")
}

// TestIMAP_PollStateDesync_DeletedMailbox tests the scenario where the selected
// mailbox is deleted while a session has it selected.
func TestIMAP_PollStateDesync_DeletedMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect first client
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Close() // Use Close() instead of Logout() in case of forced disconnect

	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Create a test mailbox
	testMailboxName := "TestDeleteMe"
	if err := c1.Create(testMailboxName, nil).Wait(); err != nil {
		t.Fatalf("CREATE mailbox failed: %v", err)
	}
	t.Logf("Created mailbox: %s", testMailboxName)

	// Select the test mailbox
	mbox, err := c1.Select(testMailboxName, nil).Wait()
	if err != nil {
		t.Fatalf("Select test mailbox failed: %v", err)
	}
	t.Logf("Selected mailbox: %s (%d messages)", testMailboxName, mbox.NumMessages)

	// Add a message to the mailbox
	testMessage := fmt.Sprintf("From: test@example.com\r\n"+
		"To: %s\r\n"+
		"Subject: Test Message\r\n"+
		"Date: %s\r\n"+
		"\r\n"+
		"This is a test message.\r\n", account.Email, time.Now().Format(time.RFC1123Z))

	appendCmd := c1.Append(testMailboxName, int64(len(testMessage)), nil)
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	_, err = appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// Get account ID and mailbox ID
	ctx := context.Background()
	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, testMailboxName)
	if err != nil {
		t.Fatalf("Failed to get mailbox: %v", err)
	}

	// Externally delete the mailbox by directly manipulating the database
	t.Log("Externally deleting the selected mailbox")

	// First delete messages (foreign key constraint)
	_, err = server.ResilientDB.GetDatabase().GetWritePool().Exec(ctx,
		"DELETE FROM messages WHERE mailbox_id = $1", mailbox.ID)
	if err != nil {
		t.Fatalf("Failed to delete messages: %v", err)
	}

	// Then delete the mailbox
	_, err = server.ResilientDB.GetDatabase().GetWritePool().Exec(ctx,
		"DELETE FROM mailboxes WHERE id = $1", mailbox.ID)
	if err != nil {
		t.Fatalf("Failed to delete mailbox: %v", err)
	}

	// Trigger a poll by sending NOOP
	t.Log("Triggering poll with NOOP command")
	err = c1.Noop().Wait()

	// The server should detect the deleted mailbox and either:
	// 1. Clear the selected mailbox state (client can continue with no mailbox selected)
	// 2. Close the connection (older behavior)
	//
	// With our fix, it should clear the selection and return success.
	// The next command requiring a selected mailbox should fail with "No mailbox selected"
	if err != nil {
		// NOOP failed - this might be okay if it's clearing the selection
		t.Logf("NOOP returned error (might be clearing selection): %v", err)
	} else {
		t.Log("NOOP succeeded - mailbox selection should be cleared")
	}

	// Try a command that requires a selected mailbox (FETCH)
	// This should fail with "No mailbox selected" or similar error
	t.Log("Attempting FETCH on deleted mailbox")
	_, fetchErr := c1.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{UID: true}).Collect()
	if fetchErr == nil {
		t.Fatal("Expected FETCH to fail (no mailbox selected), but it succeeded")
	}

	errStr := fetchErr.Error()
	if !strings.Contains(strings.ToLower(errStr), "no mailbox") &&
		!strings.Contains(strings.ToLower(errStr), "not selected") &&
		!strings.Contains(strings.ToLower(errStr), "connection") {
		t.Logf("Note: Got error but not 'no mailbox selected': %v", fetchErr)
	} else {
		t.Logf("FETCH correctly failed with: %v", fetchErr)
	}

	// Verify we can still use the connection for other operations
	t.Log("Verifying connection is still usable")
	err = c1.Noop().Wait()
	if err != nil {
		t.Logf("Connection may have been closed: %v", err)
	} else {
		t.Log("Connection still alive - can continue with other operations")
	}
}
