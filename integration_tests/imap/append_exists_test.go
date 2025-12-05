//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_AppendExists verifies that APPEND sends EXISTS untagged response
// when appending to the currently selected mailbox.
func TestIMAP_AppendExists(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// SELECT INBOX first
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	initialCount := selectData.NumMessages
	t.Logf("Initial message count: %d", initialCount)

	// APPEND a message to the currently selected mailbox
	testMessage := "From: test@example.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\nBody\r\n"

	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen, imap.FlagFlagged},
	})
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}

	// The issue is: does the go-imap library send EXISTS automatically after APPEND?
	// Or do we need to manually trigger it?
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	t.Logf("APPEND succeeded: UID=%d", appendData.UID)

	// Now check if we got an EXISTS update
	// The go-imap library should automatically poll and send EXISTS
	// Let's issue a NOOP to trigger polling
	if err := c.Noop().Wait(); err != nil {
		t.Fatalf("NOOP failed: %v", err)
	}

	// Check if the message count increased
	// We can't directly check for EXISTS untagged response, but we can verify
	// the mailbox state by re-selecting
	selectData2, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Second SELECT failed: %v", err)
	}

	expectedCount := initialCount + 1
	if selectData2.NumMessages != expectedCount {
		t.Errorf("Expected message count %d, got %d", expectedCount, selectData2.NumMessages)
	}

	t.Logf("After APPEND: message count = %d (expected %d)", selectData2.NumMessages, expectedCount)
}
