//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_ExpungeUIDInvariant verifies that UIDs remain stable after EXPUNGE.
// RFC 3501: "Unique identifiers are assigned in a strictly ascending order"
// and "The unique identifier of a message MUST NOT change during the session"
func TestIMAP_ExpungeUIDInvariant(t *testing.T) {
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

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	// Append 4 messages
	for i := 1; i <= 4; i++ {
		msg := "From: test@example.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\nBody\r\n"
		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := appendCmd.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND %d write failed: %v", i, err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND %d close failed: %v", i, err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND %d failed: %v", i, err)
		}
	}

	// Fetch all UIDs - should be 1,2,3,4
	initialFetch, err := c.Fetch(imap.SeqSetNum(1, 2, 3, 4), &imap.FetchOptions{
		UID: true,
	}).Collect()
	if err != nil {
		t.Fatalf("Initial FETCH failed: %v", err)
	}

	if len(initialFetch) != 4 {
		t.Fatalf("Expected 4 messages, got %d", len(initialFetch))
	}

	t.Logf("Initial state:")
	for i, msg := range initialFetch {
		t.Logf("  Sequence %d: UID %d", i+1, msg.UID)
	}

	// Mark messages 1 and 3 as \Deleted
	if _, err := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Collect(); err != nil {
		t.Fatalf("STORE deleted flag on seq 1 failed: %v", err)
	}

	if _, err := c.Store(imap.SeqSetNum(3), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Collect(); err != nil {
		t.Fatalf("STORE deleted flag on seq 3 failed: %v", err)
	}

	// EXPUNGE - should remove messages with UIDs 1 and 3
	expungeCmd := c.Expunge()
	for {
		seqNum := expungeCmd.Next()
		if seqNum == 0 {
			break
		}
		t.Logf("Expunged sequence: %d", seqNum)
	}
	if err := expungeCmd.Close(); err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}

	// After EXPUNGE:
	// - Sequence 1 should have UID 2
	// - Sequence 2 should have UID 4
	// UIDs never change - only sequence numbers shift

	afterFetch, err := c.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{
		UID: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH after EXPUNGE failed: %v", err)
	}

	if len(afterFetch) != 2 {
		t.Fatalf("Expected 2 messages after EXPUNGE, got %d", len(afterFetch))
	}

	t.Logf("After EXPUNGE:")
	for i, msg := range afterFetch {
		t.Logf("  Sequence %d: UID %d", i+1, msg.UID)
	}

	// Verify UIDs
	if afterFetch[0].UID != 2 {
		t.Errorf("Sequence 1 should have UID 2, got %d", afterFetch[0].UID)
	}

	if afterFetch[1].UID != 4 {
		t.Errorf("Sequence 2 should have UID 4, got %d", afterFetch[1].UID)
	}

	// Fetch sequence 2 specifically - should return UID 4
	seq2Fetch, err := c.Fetch(imap.SeqSetNum(2), &imap.FetchOptions{
		UID: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH seq 2 failed: %v", err)
	}

	if len(seq2Fetch) != 1 {
		t.Fatalf("Expected 1 message for seq 2, got %d", len(seq2Fetch))
	}

	if seq2Fetch[0].UID != 4 {
		t.Errorf("RFC 3501 violation: Sequence 2 should have UID 4, but got UID %d", seq2Fetch[0].UID)
		t.Error("UIDs must never change during a session!")
	}
}
