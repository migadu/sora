//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func containsCI(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func appendTestMsg(t *testing.T, c *imapclient.Client, mailbox string, subject string) {
	t.Helper()
	msg := fmt.Sprintf("From: test@example.com\r\nTo: user@example.com\r\nSubject: %s\r\n\r\nBody of %s\r\n", subject, subject)
	appendCmd := c.Append(mailbox, int64(len(msg)), &imap.AppendOptions{})
	if _, err := appendCmd.Write([]byte(msg)); err != nil {
		t.Fatalf("Failed to write append data: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("Failed to close append: %v", err)
	}
}

// TestMOVE_COPYUID_Ordering verifies that MOVE returns correct COPYUID
// source→dest UID pairings. This tests for a potential bug where Go map
// iteration randomness could break the 1:1 UID correspondence.
func TestMOVE_COPYUID_Ordering(t *testing.T) {
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

	if err := c.Create("Archive", nil).Wait(); err != nil {
		// Ignore "already exists" from previous test runs
		if !containsCI(err.Error(), "ALREADYEXISTS") {
			t.Fatalf("Failed to create Archive: %v", err)
		}
	}

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Failed to select INBOX: %v", err)
	}

	// Append 5 messages with distinct subjects
	for i := 1; i <= 5; i++ {
		appendTestMsg(t, c, "INBOX", fmt.Sprintf("Message %d", i))
	}

	// Re-select to get updated state
	selData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Failed to re-select INBOX: %v", err)
	}
	if selData.NumMessages != 5 {
		t.Fatalf("Expected 5 messages, got %d", selData.NumMessages)
	}

	// Move messages with UIDs 1,3,5 to Archive
	moveCmd := c.Move(imap.UIDSetNum(1, 3, 5), "Archive")
	moveData, err := moveCmd.Wait()
	if err != nil {
		t.Fatalf("MOVE failed: %v", err)
	}

	if moveData == nil {
		t.Fatal("MOVE returned no COPYUID data")
	}

	t.Logf("COPYUID: source=%v dest=%v", moveData.SourceUIDs, moveData.DestUIDs)

	sourceUIDSet, ok := moveData.SourceUIDs.(imap.UIDSet)
	if !ok {
		t.Fatalf("SourceUIDs is not a UIDSet: %T", moveData.SourceUIDs)
	}
	destUIDSet, ok := moveData.DestUIDs.(imap.UIDSet)
	if !ok {
		t.Fatalf("DestUIDs is not a UIDSet: %T", moveData.DestUIDs)
	}
	sourceUIDs := uidSetToSlice(sourceUIDSet)
	destUIDs := uidSetToSlice(destUIDSet)

	if len(sourceUIDs) != 3 || len(destUIDs) != 3 {
		t.Fatalf("Expected 3 UIDs each, got source=%d dest=%d", len(sourceUIDs), len(destUIDs))
	}

	// Verify source UIDs are sorted
	for i := 1; i < len(sourceUIDs); i++ {
		if sourceUIDs[i] <= sourceUIDs[i-1] {
			t.Errorf("Source UIDs not sorted: %v", sourceUIDs)
		}
	}

	// Verify dest UIDs are sorted
	for i := 1; i < len(destUIDs); i++ {
		if destUIDs[i] <= destUIDs[i-1] {
			t.Errorf("Dest UIDs not sorted: %v", destUIDs)
		}
	}

	// Verify pairing: fetch from Archive and check subjects match source order
	if _, err := c.Select("Archive", nil).Wait(); err != nil {
		t.Fatalf("Failed to select Archive: %v", err)
	}

	fetchCmd := c.Fetch(imap.SeqSet{{Start: 1, Stop: 0}}, &imap.FetchOptions{Envelope: true, UID: true})
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH from Archive failed: %v", err)
	}

	if len(msgs) != 3 {
		t.Fatalf("Expected 3 messages in Archive, got %d", len(msgs))
	}

	// Messages should be "Message 1", "Message 3", "Message 5" in UID order
	expectedSubjects := []string{"Message 1", "Message 3", "Message 5"}
	for i, msg := range msgs {
		t.Logf("Archive[%d]: UID=%d Subject=%q", i, msg.UID, msg.Envelope.Subject)
		if msg.Envelope.Subject != expectedSubjects[i] {
			t.Errorf("Message %d: expected Subject=%q, got %q (COPYUID pairing may be wrong)",
				i, expectedSubjects[i], msg.Envelope.Subject)
		}
	}

	t.Log("✓ MOVE COPYUID ordering verified")
}

// TestCOPY_ToSameMailbox verifies that COPY to the same mailbox returns
// a proper IMAP error, not an internal server error.
func TestCOPY_ToSameMailbox(t *testing.T) {
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

	appendTestMsg(t, c, "INBOX", "Test message")

	// Re-select
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Failed to re-select INBOX: %v", err)
	}

	// Copy message 1 to same mailbox (INBOX)
	// RFC 3501 §6.4.7 does not prohibit this — server may allow or reject it.
	// But it MUST NOT return an internal server error (that indicates a bug).
	copyCmd := c.Copy(imap.SeqSetNum(1), "INBOX")
	_, err = copyCmd.Wait()
	if err != nil {
		errStr := err.Error()
		// An IMAP NO response is acceptable. An internal server error is a bug.
		if containsCI(errStr, "internal") || containsCI(errStr, "SERVERBUG") {
			t.Errorf("COPY to same mailbox returned internal server error (bug): %v", err)
		} else {
			t.Logf("✓ COPY to same mailbox properly rejected: %v", err)
		}
	} else {
		t.Log("✓ COPY to same mailbox succeeded (allowed by implementation)")
	}
}

// TestDELETE_SelectedMailbox verifies behavior when deleting the currently selected mailbox.
func TestDELETE_SelectedMailbox(t *testing.T) {
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

	// Create and select a test mailbox
	if err := c.Create("TestDelete", nil).Wait(); err != nil {
		t.Fatalf("Failed to create TestDelete: %v", err)
	}

	if _, err := c.Select("TestDelete", nil).Wait(); err != nil {
		t.Fatalf("Failed to select TestDelete: %v", err)
	}

	appendTestMsg(t, c, "TestDelete", "Doomed message")

	// Try to delete the currently selected mailbox
	err = c.Delete("TestDelete").Wait()
	if err != nil {
		t.Logf("DELETE selected mailbox returned error: %v", err)
		t.Log("✓ DELETE of selected mailbox rejected (safe behavior)")
	} else {
		t.Log("⚠ DELETE of selected mailbox succeeded — verify session state is still valid")

		// Try to fetch from the (now deleted) mailbox to verify session isn't corrupted
		fetchCmd := c.Fetch(imap.SeqSet{{Start: 1, Stop: 0}}, &imap.FetchOptions{Envelope: true})
		_, fetchErr := fetchCmd.Collect()
		if fetchErr != nil {
			t.Logf("FETCH after DELETE returned error: %v (expected — mailbox gone)", fetchErr)
		}
	}
}

// uidSetToSlice converts a UIDSet to a flat slice of UIDs
func uidSetToSlice(set imap.UIDSet) []imap.UID {
	var uids []imap.UID
	for _, r := range set {
		for uid := r.Start; uid <= r.Stop; uid++ {
			uids = append(uids, uid)
		}
	}
	return uids
}
