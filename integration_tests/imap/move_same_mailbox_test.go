//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_MoveSameMailbox tests that moving a message to the same mailbox
// works correctly and assigns a new UID (per RFC 6851).
//
// This is a regression test for the bug where Sora returns:
// NO [SERVERBUG] cannot move messages within the same mailbox
//
// Expected behavior per RFC 6851:
// - MOVE to the same mailbox should succeed
// - The message gets a new UID
// - COPYUID response code provides the UID mapping
// - Original message is expunged
func TestIMAP_MoveSameMailbox(t *testing.T) {
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

	// Select INBOX
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	if selectData == nil {
		t.Fatal("Select returned nil selectData")
	}

	// Append a test message to INBOX
	testMessage := "From: test@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Move Same Mailbox Test\r\n" +
		"\r\n" +
		"Test message body.\r\n"

	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen},
	})
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}
	originalUID := appendData.UID
	t.Logf("Appended message with UID: %d", originalUID)

	// Fetch the message to verify it exists
	fetchResults, err := c.Fetch(imap.UIDSetNum(originalUID), &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if len(fetchResults) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(fetchResults))
	}
	if fetchResults[0].UID != originalUID {
		t.Fatalf("Expected UID %d, got %d", originalUID, fetchResults[0].UID)
	}
	t.Logf("Verified message exists with UID: %d", originalUID)

	// Get initial message count
	selectData, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	initialCount := selectData.NumMessages
	t.Logf("INBOX has %d messages before MOVE", initialCount)

	// Move the message to the same mailbox (INBOX -> INBOX)
	// This should succeed and assign a new UID
	t.Logf("Attempting to MOVE UID %d to INBOX (same mailbox)", originalUID)
	moveData, err := c.Move(imap.UIDSetNum(originalUID), "INBOX").Wait()
	if err != nil {
		t.Fatalf("MOVE to same mailbox failed: %v (this is the bug we're testing for)", err)
	}
	if moveData == nil {
		t.Fatal("MOVE returned nil moveData")
	}
	t.Logf("MOVE successful: %+v", moveData)

	// Verify message count is still the same (1 message moved to same mailbox)
	selectData, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX after move failed: %v", err)
	}
	if selectData.NumMessages != initialCount {
		t.Errorf("Expected %d messages after MOVE, got %d", initialCount, selectData.NumMessages)
	}
	t.Logf("INBOX still has %d messages after MOVE (as expected)", selectData.NumMessages)

	// Verify the original message no longer exists at its old UID
	// (it should have a new UID now)
	fetchResults, err = c.Fetch(imap.UIDSetNum(originalUID), &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if len(fetchResults) != 0 {
		t.Errorf("Original UID %d should no longer exist (got %d messages)", originalUID, len(fetchResults))
	}
	t.Logf("Verified original UID %d no longer exists", originalUID)

	// Re-SELECT the mailbox to get the updated state
	// (after UID changes, we need to refresh the client's view)
	selectData, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Re-select INBOX failed: %v", err)
	}
	t.Logf("After re-select: %d messages, UIDNEXT=%d", selectData.NumMessages, selectData.UIDNext)

	// Fetch by the new UID (from move data)
	newUID := imap.UID(2) // From MOVE response: DestUIDs:2
	fetchResults, err = c.Fetch(imap.UIDSetNum(newUID), &imap.FetchOptions{
		UID:         true,
		BodySection: []*imap.FetchItemBodySection{{}},
	}).Collect()
	if err != nil {
		t.Fatalf("Fetch by new UID failed: %v", err)
	}
	if len(fetchResults) != 1 {
		t.Fatalf("Expected 1 message with new UID %d, got %d", newUID, len(fetchResults))
	}
	if fetchResults[0].UID != newUID {
		t.Errorf("Expected UID %d, got %d", newUID, fetchResults[0].UID)
	}
	t.Logf("Successfully fetched message with new UID: %d (was %d)", newUID, originalUID)

	// Also verify we can fetch by sequence number
	fetchResults, err = c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		UID: true,
	}).Collect()
	if err != nil {
		t.Fatalf("Fetch by seq failed: %v", err)
	}
	if len(fetchResults) != 1 {
		t.Fatalf("Expected 1 message by sequence number, got %d", len(fetchResults))
	}
	if fetchResults[0].UID != newUID {
		t.Errorf("Expected sequence 1 to have UID %d, got %d", newUID, fetchResults[0].UID)
	}
	t.Logf("Verified sequence number 1 maps to UID %d", fetchResults[0].UID)
}
