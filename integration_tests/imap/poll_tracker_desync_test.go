//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_PollTrackerDesync_ExpungeOnEmptyMailbox tests the scenario where:
// 1. Mailbox becomes empty (0 messages in DB)
// 2. Poll receives an expunge update for seq 1
// 3. Tracker already at 0, so QueueExpunge would panic
// This was the first panic we fixed in poll.go
func TestIMAP_PollTrackerDesync_ExpungeOnEmptyMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect client 1
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Close()

	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Select INBOX
	mbox, err := c1.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	t.Logf("Initial mailbox state: %d messages", mbox.NumMessages)

	// Add 1 test message
	testMessage := fmt.Sprintf("From: test@example.com\r\n"+
		"To: %s\r\n"+
		"Subject: Test Message\r\n"+
		"Date: %s\r\n"+
		"\r\n"+
		"This is test message.\r\n", account.Email, time.Now().Format(time.RFC1123Z))

	appendCmd := c1.Append("INBOX", int64(len(testMessage)), nil)
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

	// Verify we have 1 message
	mbox, err = c1.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	if mbox.NumMessages != 1 {
		t.Fatalf("Expected 1 message, got %d", mbox.NumMessages)
	}
	t.Logf("Added 1 message, total: %d", mbox.NumMessages)

	// Get account and mailbox for DB manipulation
	ctx := context.Background()
	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatalf("Failed to get mailbox: %v", err)
	}

	// Simulate the race condition:
	// 1. Mark message as expunged (soft delete)
	t.Log("Marking message as expunged via direct database manipulation")
	_, err = server.ResilientDB.GetDatabase().GetWritePool().Exec(ctx,
		"UPDATE messages SET expunged_at = NOW() WHERE mailbox_id = $1 AND uid = 1",
		mailbox.ID)
	if err != nil {
		t.Fatalf("Failed to mark message as expunged: %v", err)
	}

	// 2. Then hard delete it (this is what the background cleaner would do)
	t.Log("Hard deleting the expunged message")
	_, err = server.ResilientDB.GetDatabase().GetWritePool().Exec(ctx,
		"DELETE FROM messages WHERE mailbox_id = $1 AND uid = 1",
		mailbox.ID)
	if err != nil {
		t.Fatalf("Failed to hard delete message: %v", err)
	}

	// Now the database has 0 messages, but the client's session might still think it has 1
	// and might have an expunge update queued for seq 1

	// Trigger a poll with NOOP - this should handle the desync gracefully
	t.Log("Triggering poll with NOOP command")
	err = c1.Noop().Wait()
	if err != nil {
		t.Logf("NOOP returned error: %v (may indicate forced reconnect)", err)
		// If we get an error, it might be a BYE forcing reconnect - that's acceptable
	} else {
		t.Log("NOOP succeeded - desync handled gracefully")
	}

	// Verify state by reconnecting
	t.Log("Reconnecting to verify correct state")
	time.Sleep(100 * time.Millisecond)

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

	if mbox.NumMessages != 0 {
		t.Errorf("Expected 0 messages after reconnect, got %d", mbox.NumMessages)
	} else {
		t.Logf("Correct state after reconnect: %d messages", mbox.NumMessages)
	}

	t.Log("Test completed - no panic occurred")
}

// TestIMAP_PollTrackerDesync_AppendWithTrackerHigher tests the scenario where:
// 1. Session has currentNumMessages = 1, but tracker has numMessages = 2 (desync)
// 2. User appends a message, DB now has 2
// 3. We try to call QueueNumMessages(2) but tracker already has 2
// 4. This would cause "cannot decrease" panic (2 is not > 2)
// OR worse: if tracker has 3, we'd try to go from 3 to 2 (decrease panic)
func TestIMAP_PollTrackerDesync_AppendWithTrackerHigher(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect client
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Close()

	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Select INBOX
	mbox, err := c1.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	t.Logf("Initial mailbox state: %d messages", mbox.NumMessages)

	// Add 2 messages
	for i := 1; i <= 2; i++ {
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

	t.Logf("Added 2 messages")

	// Get account and mailbox
	ctx := context.Background()
	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatalf("Failed to get mailbox: %v", err)
	}

	// Simulate desync: Delete one message directly from DB
	// This creates a state where DB has 1 message, but session might think it has 2
	t.Log("Deleting one message via direct database manipulation to create desync")
	_, err = server.ResilientDB.GetDatabase().GetWritePool().Exec(ctx,
		"DELETE FROM messages WHERE mailbox_id = $1 AND uid = 1",
		mailbox.ID)
	if err != nil {
		t.Fatalf("Failed to delete message: %v", err)
	}

	// Now append a new message - this should trigger the desync handling in append.go
	// The session might still think mailbox has 2 messages (or tracker has wrong count)
	// After append, DB will have 2 messages (we deleted UID 1, still have UID 2, now adding UID 3)
	t.Log("Appending new message - this may trigger desync detection")
	testMessage := fmt.Sprintf("From: test@example.com\r\n"+
		"To: %s\r\n"+
		"Subject: Test Message After Desync\r\n"+
		"Date: %s\r\n"+
		"\r\n"+
		"This message is appended after desync.\r\n", account.Email, time.Now().Format(time.RFC1123Z))

	appendCmd := c1.Append("INBOX", int64(len(testMessage)), nil)
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

	t.Log("APPEND succeeded - no panic occurred")

	// Trigger a NOOP to see if state reconciles
	t.Log("Triggering NOOP to reconcile state")
	err = c1.Noop().Wait()
	if err != nil {
		t.Logf("NOOP returned error: %v", err)
	}

	// Verify final state
	mbox, err = c1.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	t.Logf("Final state: %d messages (expected 2: UID 2 and UID 3)", mbox.NumMessages)
	if mbox.NumMessages != 2 {
		t.Errorf("Expected 2 messages, got %d", mbox.NumMessages)
	}

	t.Log("Test completed - no panic occurred, state reconciled")
}
