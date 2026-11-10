//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/go-imap/imapclient"
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

	// Trigger a poll with NOOP - this should detect the hard delete and force a disconnect
	t.Log("Triggering poll with NOOP command")
	err = c1.Noop().Wait()
	if err == nil {
		t.Fatal("Expected NOOP to return an error (BYE) due to desync, but it succeeded")
	}
	t.Logf("NOOP returned expected error (BYE forcing reconnect): %v", err)

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
// 1. Session syncs to N messages via Poll (NOOP)
// 2. A message is hard-deleted from the DB (simulating background cleanup)
// 3. DB now has N-1 messages, but session still thinks N
// 4. Next Poll (via NOOP) detects the count mismatch and forces BYE
// This ensures hard-deletes outside the MODSEQ window cause a safe reconnect.
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

	// Add 3 messages
	for i := 1; i <= 3; i++ {
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

	t.Logf("Added 3 messages")

	// Force a Poll so the session discovers the 3 messages.
	// APPEND has sendOK=false in go-imap, so Poll is NOT called after APPEND.
	// The session only learns about new messages when Poll runs (e.g., during NOOP).
	if err := c1.Noop().Wait(); err != nil {
		t.Fatalf("NOOP (sync) failed: %v", err)
	}
	t.Log("Session synced via NOOP - session now knows about 3 messages")

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

	// Simulate hard-delete by background cleanup worker: delete one message directly from DB.
	// This creates a state where DB has 2 messages, but session thinks it has 3.
	t.Log("Hard-deleting one message via direct database manipulation to create desync")
	_, err = server.ResilientDB.GetDatabase().GetWritePool().Exec(ctx,
		"DELETE FROM messages WHERE mailbox_id = $1 AND uid = 1",
		mailbox.ID)
	if err != nil {
		t.Fatalf("Failed to delete message: %v", err)
	}

	// NOOP triggers Poll which detects session_count(3) > db_count(2)
	// and forces a BYE to rebuild the tracker from scratch.
	t.Log("Triggering NOOP to force poll and desync detection")
	err = c1.Noop().Wait()
	if err == nil {
		t.Fatal("Expected NOOP to return an error (BYE) due to desync, but it succeeded")
	}
	t.Logf("NOOP returned expected error (BYE forcing reconnect): %v", err)

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

	// Verify final state
	mbox, err = c2.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	t.Logf("Final state: %d messages (expected 2: UID 2 and UID 3)", mbox.NumMessages)
	if mbox.NumMessages != 2 {
		t.Errorf("Expected 2 messages, got %d", mbox.NumMessages)
	}

	t.Log("Test completed - desync handled by BYE correctly")
}
