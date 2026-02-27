//go:build integration

package imap_test

import (
	"fmt"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestEXPUNGE_TrackerDesync verifies that EXPUNGE doesn't cause tracker desync
// which would force a BYE disconnect on the next poll.
// This tests the same bug class as the MOVE tracker desync that was already fixed.
func TestEXPUNGE_TrackerDesync(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer c.Close()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Failed to select INBOX: %v", err)
	}

	// Append 3 messages
	for i := 1; i <= 3; i++ {
		msg := fmt.Sprintf("From: test@example.com\r\nTo: user@example.com\r\nSubject: Msg %d\r\n\r\nBody %d\r\n", i, i)
		appendCmd := c.Append("INBOX", int64(len(msg)), &imap.AppendOptions{})
		if _, err := appendCmd.Write([]byte(msg)); err != nil {
			t.Fatalf("Failed to write append: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("Failed to close append: %v", err)
		}
	}

	// Re-select to see new messages
	selData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Failed to re-select INBOX: %v", err)
	}
	if selData.NumMessages != 3 {
		t.Fatalf("Expected 3 messages, got %d", selData.NumMessages)
	}

	// Mark message 2 as \Deleted
	storeCmd := c.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	// EXPUNGE
	if err := c.Expunge().Close(); err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}

	// Critical: NOOP to trigger poll — if tracker is desynced, this will cause BYE disconnect
	if err := c.Noop().Wait(); err != nil {
		t.Errorf("NOOP after EXPUNGE failed (tracker desync?): %v", err)
	}

	// Verify we still have a working session by fetching remaining messages
	fetchCmd := c.Fetch(imap.SeqSet{{Start: 1, Stop: 0}}, &imap.FetchOptions{
		Envelope: true,
		UID:      true,
	})
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Errorf("FETCH after EXPUNGE+NOOP failed (session corrupted?): %v", err)
	}

	if len(msgs) != 2 {
		t.Errorf("Expected 2 messages after expunge, got %d", len(msgs))
	}

	for _, msg := range msgs {
		t.Logf("Remaining: UID=%d Subject=%q", msg.UID, msg.Envelope.Subject)
	}

	t.Log("✓ EXPUNGE tracker desync test passed — session remains valid after EXPUNGE+NOOP")
}
