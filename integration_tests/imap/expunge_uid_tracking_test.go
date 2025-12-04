//go:build integration

package imap_test

import (
	"fmt"
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestExpungeUIDTracking tests that UID-to-sequence mapping remains correct after EXPUNGE
// This reproduces imaptest "expunge command" tests 5-6 and "expunge2 command" test 4
// which showed UID tracking corruption after EXPUNGE operations.
func TestExpungeUIDTracking(t *testing.T) {
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
		t.Fatalf("Select failed: %v", err)
	}

	// Append 4 messages and track their UIDs
	var uids []imap.UID
	for i := 1; i <= 4; i++ {
		msg := fmt.Sprintf("Subject: msg%d\r\n\r\nbody%d", i, i)
		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := appendCmd.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		data, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
		if data.UID != 0 {
			uids = append(uids, data.UID)
		}
	}

	// If UIDs weren't returned by APPEND, fetch them
	if len(uids) < 4 {
		fetchCmd := c.Fetch(imap.SeqSetNum(1, 2, 3, 4), &imap.FetchOptions{
			UID: true,
		})
		msgs, err := fetchCmd.Collect()
		if err != nil {
			t.Fatalf("FETCH UIDs failed: %v", err)
		}
		uids = nil
		for _, msg := range msgs {
			uids = append(uids, msg.UID)
		}
	}

	if len(uids) != 4 {
		t.Fatalf("Expected 4 UIDs, got %d", len(uids))
	}

	t.Logf("Original UIDs: %v (UID1=%d, UID2=%d, UID3=%d, UID4=%d)",
		uids, uids[0], uids[1], uids[2], uids[3])

	// Mark messages at sequences 1 and 3 as \Deleted
	if err := c.Store(imap.SeqSetNum(1, 3), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		t.Fatalf("STORE \\Deleted failed: %v", err)
	}

	t.Logf("Marked sequences 1 and 3 (UIDs %d and %d) as \\Deleted", uids[0], uids[2])

	// EXPUNGE - this should remove messages with UIDs[0] and UIDs[2]
	if err := c.Expunge().Close(); err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}

	t.Log("EXPUNGE completed")

	// After EXPUNGE:
	// - Original message 2 (UID uids[1]) should now be at sequence 1
	// - Original message 4 (UID uids[3]) should now be at sequence 2
	// Total: 2 messages remaining

	// THIS IS THE CRITICAL TEST: Fetch UIDs by sequence number
	// According to imaptest, this is where the bug manifests
	t.Log("Fetching sequences 1,2 to verify UID mapping...")

	fetchCmd := c.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{
		UID: true,
	})

	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH after EXPUNGE failed (connection may have died): %v", err)
	}

	if len(msgs) != 2 {
		t.Fatalf("Expected 2 messages after EXPUNGE, got %d", len(msgs))
	}

	// Verify the UID mapping is correct
	expectedUID1 := uids[1] // Original message 2
	expectedUID2 := uids[3] // Original message 4

	t.Logf("Expected sequence 1 -> UID %d, got UID %d", expectedUID1, msgs[0].UID)
	t.Logf("Expected sequence 2 -> UID %d, got UID %d", expectedUID2, msgs[1].UID)

	if msgs[0].UID != expectedUID1 {
		t.Errorf("EXPUNGE UID TRACKING BUG: Sequence 1 should have UID %d, got %d",
			expectedUID1, msgs[0].UID)
	}

	if msgs[1].UID != expectedUID2 {
		t.Errorf("EXPUNGE UID TRACKING BUG: Sequence 2 should have UID %d, got %d",
			expectedUID2, msgs[1].UID)
	}

	// Verify connection is still alive by doing another operation
	t.Log("Verifying connection is still alive...")
	fetchCmd = c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		UID: true,
	})
	msgs, err = fetchCmd.Collect()
	if err != nil {
		t.Fatalf("Connection died after EXPUNGE: %v", err)
	}
	if len(msgs) != 1 {
		t.Errorf("Expected 1 message from second fetch, got %d", len(msgs))
	}

	t.Log("✓ Connection still alive after EXPUNGE")
	t.Log("✓ UID tracking test completed successfully")
}

// TestExpungeUIDTrackingMultipleExpunges tests UID tracking with multiple EXPUNGE operations
func TestExpungeUIDTrackingMultipleExpunges(t *testing.T) {
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
		t.Fatalf("Select failed: %v", err)
	}

	// Append 6 messages
	var uids []imap.UID
	for i := 1; i <= 6; i++ {
		msg := fmt.Sprintf("Subject: msg%d\r\n\r\nbody%d", i, i)
		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := appendCmd.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		data, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
		if data.UID != 0 {
			uids = append(uids, data.UID)
		}
	}

	if len(uids) < 6 {
		fetchCmd := c.Fetch(imap.SeqSetNum(1, 2, 3, 4, 5, 6), &imap.FetchOptions{UID: true})
		msgs, err := fetchCmd.Collect()
		if err != nil {
			t.Fatalf("FETCH UIDs failed: %v", err)
		}
		uids = nil
		for _, msg := range msgs {
			uids = append(uids, msg.UID)
		}
	}

	t.Logf("Original 6 messages with UIDs: %v", uids)

	// First expunge: Delete message 2 (sequence 2, UID uids[1])
	if err := c.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		t.Fatalf("STORE \\Deleted failed: %v", err)
	}

	if err := c.Expunge().Close(); err != nil {
		t.Fatalf("First EXPUNGE failed: %v", err)
	}

	t.Log("First EXPUNGE completed (removed message with UID", uids[1], ")")

	// Now we have 5 messages: UIDs[0,2,3,4,5]
	// Sequences: 1=UID[0], 2=UID[2], 3=UID[3], 4=UID[4], 5=UID[5]

	// Second expunge: Delete message at sequence 3 (was original message 4, UID uids[3])
	if err := c.Store(imap.SeqSetNum(3), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		t.Fatalf("STORE \\Deleted failed: %v", err)
	}

	if err := c.Expunge().Close(); err != nil {
		t.Fatalf("Second EXPUNGE failed: %v", err)
	}

	t.Log("Second EXPUNGE completed (removed message with UID", uids[3], ")")

	// Now we have 4 messages: UIDs[0,2,4,5]
	// Sequences: 1=UID[0], 2=UID[2], 3=UID[4], 4=UID[5]

	// Verify all UIDs are correct
	fetchCmd := c.Fetch(imap.SeqSetNum(1, 2, 3, 4), &imap.FetchOptions{UID: true})
	msgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH after second EXPUNGE failed: %v", err)
	}

	if len(msgs) != 4 {
		t.Fatalf("Expected 4 messages, got %d", len(msgs))
	}

	expectedUIDs := []imap.UID{uids[0], uids[2], uids[4], uids[5]}
	for i, msg := range msgs {
		t.Logf("Sequence %d -> UID %d (expected %d)", i+1, msg.UID, expectedUIDs[i])
		if msg.UID != expectedUIDs[i] {
			t.Errorf("Sequence %d: expected UID %d, got %d", i+1, expectedUIDs[i], msg.UID)
		}
	}

	t.Log("✓ Multiple EXPUNGE UID tracking test completed successfully")
}

// TestExpungeUIDTrackingWithFetch tests the specific imaptest scenario:
// FETCH specific sequences after EXPUNGE to verify UID consistency
func TestExpungeUIDTrackingWithFetch(t *testing.T) {
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
		t.Fatalf("Select failed: %v", err)
	}

	// Append 4 messages
	for i := 1; i <= 4; i++ {
		msg := fmt.Sprintf("Subject: msg%d\r\n\r\nbody%d", i, i)
		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := appendCmd.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
	}

	// Get all UIDs before EXPUNGE
	fetchCmd := c.Fetch(imap.SeqSetNum(1, 2, 3, 4), &imap.FetchOptions{UID: true})
	msgsBefore, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH before EXPUNGE failed: %v", err)
	}

	if len(msgsBefore) != 4 {
		t.Fatalf("Expected 4 messages before EXPUNGE, got %d", len(msgsBefore))
	}

	t.Logf("Before EXPUNGE:")
	for i, msg := range msgsBefore {
		t.Logf("  Sequence %d -> UID %d", i+1, msg.UID)
	}

	// Store original UIDs
	_ = msgsBefore[0].UID // uid1 - will be deleted
	uid2 := msgsBefore[1].UID
	_ = msgsBefore[2].UID // uid3 - will be deleted
	uid4 := msgsBefore[3].UID

	// Mark sequences 1 and 3 for deletion
	if err := c.Store(imap.SeqSetNum(1, 3), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		t.Fatalf("STORE \\Deleted failed: %v", err)
	}

	// EXPUNGE
	if err := c.Expunge().Close(); err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}

	// This is the critical test from imaptest: "fetch 2,4 (uid)"
	// After expunge, we only have 2 messages, so this should fetch sequences 1,2
	// But the imaptest original command tries to fetch what WERE sequences 2,4
	// which are now sequences 1,2 after expunge

	// According to the imaptest failure:
	// Error: user@domain.com[16]: UID changed for sequence 2: 4 -> 2: * 2 FETCH (UID 2)
	// This suggests the server is returning wrong UIDs

	t.Log("After EXPUNGE (should have 2 messages remaining):")

	// Fetch all remaining messages (we know there are 2 after expunging 2)
	fetchCmd = c.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{UID: true})
	msgsAfter, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH after EXPUNGE failed: %v", err)
	}

	if len(msgsAfter) != 2 {
		t.Fatalf("Expected 2 messages after EXPUNGE, got %d", len(msgsAfter))
	}

	// After expunging sequences 1,3 (UIDs uid1, uid3):
	// Sequence 1 should now be UID uid2 (was sequence 2)
	// Sequence 2 should now be UID uid4 (was sequence 4)

	for i, msg := range msgsAfter {
		t.Logf("  Sequence %d -> UID %d", i+1, msg.UID)
	}

	if msgsAfter[0].UID != uid2 {
		t.Errorf("After EXPUNGE: Sequence 1 should be UID %d (was sequence 2), got UID %d",
			uid2, msgsAfter[0].UID)
	}

	if msgsAfter[1].UID != uid4 {
		t.Errorf("After EXPUNGE: Sequence 2 should be UID %d (was sequence 4), got UID %d",
			uid4, msgsAfter[1].UID)
	}

	t.Log("✓ EXPUNGE with FETCH UID tracking test completed successfully")
}
