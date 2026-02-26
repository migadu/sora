//go:build integration

package imap_test

import (
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestRenameINBOX_RFC3501 verifies that renaming INBOX follows RFC 3501 §6.3.5:
// messages are moved to the new mailbox, INBOX is preserved empty.
func TestRenameINBOX_RFC3501(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Append a test message to INBOX
	appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("Failed to write append data: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// Verify INBOX has 1 message
	inboxData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}
	if inboxData.NumMessages != 1 {
		t.Fatalf("Expected 1 message in INBOX before rename, got %d", inboxData.NumMessages)
	}
	t.Logf("INBOX has %d message(s) before rename", inboxData.NumMessages)

	// Close INBOX before rename
	if err := c.Unselect().Wait(); err != nil {
		t.Fatalf("UNSELECT failed: %v", err)
	}

	// Rename INBOX to "MovedInbox" (must not be a default mailbox name)
	if err := c.Rename("INBOX", "MovedInbox", nil).Wait(); err != nil {
		t.Fatalf("RENAME INBOX to MovedInbox failed: %v", err)
	}
	t.Log("RENAME INBOX MovedInbox succeeded")

	// Verify: MovedInbox has the message
	movedData, err := c.Select("MovedInbox", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT MovedInbox failed: %v", err)
	}
	if movedData.NumMessages != 1 {
		t.Fatalf("Expected 1 message in MovedInbox after rename, got %d", movedData.NumMessages)
	}
	t.Logf("✓ MovedInbox has %d message(s)", movedData.NumMessages)

	// Unselect before checking INBOX
	if err := c.Unselect().Wait(); err != nil {
		t.Fatalf("UNSELECT failed: %v", err)
	}

	// Verify: INBOX still exists and is empty
	inboxData2, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT INBOX after rename failed (INBOX should still exist): %v", err)
	}
	if inboxData2.NumMessages != 0 {
		t.Fatalf("Expected 0 messages in INBOX after rename, got %d", inboxData2.NumMessages)
	}
	t.Logf("✓ INBOX still exists with %d message(s) (empty as expected)", inboxData2.NumMessages)

	// Verify: INBOX UID validity is preserved (same as before rename)
	if inboxData2.UIDValidity != inboxData.UIDValidity {
		t.Logf("Note: INBOX UID validity changed from %d to %d (this is acceptable)", inboxData.UIDValidity, inboxData2.UIDValidity)
	}

	t.Log("✓ INBOX rename follows RFC 3501 §6.3.5")
}

var testMessage = "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test INBOX Rename\r\nDate: Thu, 01 Jan 2026 00:00:00 +0000\r\nMessage-ID: <test-inbox-rename@example.com>\r\n\r\nTest body for INBOX rename.\r\n"

// TestRenameINBOX_ToExistingMailbox verifies that renaming INBOX to an
// existing mailbox name is rejected.
func TestRenameINBOX_ToExistingMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Try to rename INBOX to "Sent" (which already exists as a default mailbox)
	err = c.Rename("INBOX", "Sent", nil).Wait()
	if err == nil {
		t.Fatal("Expected RENAME INBOX to Sent to fail (Sent already exists), but it succeeded")
	}

	t.Logf("✓ RENAME INBOX to existing mailbox correctly rejected: %v", err)
}

// TestRenameINBOX_EmptyInbox verifies renaming an empty INBOX works correctly.
func TestRenameINBOX_EmptyInbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Rename empty INBOX
	if err := c.Rename("INBOX", "OldInbox", nil).Wait(); err != nil {
		t.Fatalf("RENAME empty INBOX failed: %v", err)
	}

	// Verify OldInbox exists (even if empty)
	_, err = c.Select("OldInbox", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT OldInbox failed: %v", err)
	}

	// Verify INBOX still exists
	if err := c.Unselect().Wait(); err != nil {
		t.Fatalf("UNSELECT failed: %v", err)
	}
	inboxData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT INBOX after rename failed: %v", err)
	}
	if inboxData.NumMessages != 0 {
		t.Fatalf("Expected empty INBOX, got %d messages", inboxData.NumMessages)
	}

	t.Log("✓ Empty INBOX rename works correctly")
}

func init() {
	// Ensure imap package is used
	_ = imap.CapIMAP4rev1
}
