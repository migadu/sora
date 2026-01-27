//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SequenceNumberConsistency_FetchAfterExternalExpunge tests that
// FETCH returns correct sequence numbers after messages are expunged externally.
// This reproduces the bug where EncodeSeqNum was called on database sequence numbers,
// causing off-by-one errors when the database renumbered sequences after expunge.
func TestIMAP_SequenceNumberConsistency_FetchAfterExternalExpunge(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect first client and keep it open
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	// Select INBOX
	if _, err := c1.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Add 10 test messages and track their UIDs
	t.Log("Adding 10 messages to mailbox")
	var uids []imap.UID
	for i := 1; i <= 10; i++ {
		testMessage := fmt.Sprintf("From: test@example.com\r\n"+
			"To: %s\r\n"+
			"Subject: Test Message %d\r\n"+
			"Date: %s\r\n"+
			"\r\n"+
			"This is test message %d.\r\n", account.Email, i, time.Now().Format(time.RFC1123Z), i)

		appendCmd := c1.Append("INBOX", int64(len(testMessage)), nil)
		if _, err = appendCmd.Write([]byte(testMessage)); err != nil {
			t.Fatalf("APPEND write message %d failed: %v", i, err)
		}
		if err = appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close message %d failed: %v", i, err)
		}
		appendData, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND message %d failed: %v", i, err)
		}
		uids = append(uids, appendData.UID)
	}

	t.Logf("Added 10 messages with UIDs: %v", uids)

	// Verify initial state: 10 messages, sequences 1-10
	mbox, err := c1.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	if mbox.NumMessages != 10 {
		t.Fatalf("Expected 10 messages, got %d", mbox.NumMessages)
	}

	// Fetch all messages to verify initial sequence numbers
	seqSet := imap.SeqSet{}
	seqSet.AddRange(1, 10)
	fetchResults, err := c1.Fetch(seqSet, &imap.FetchOptions{UID: true}).Collect()
	if err != nil {
		t.Fatalf("Initial FETCH failed: %v", err)
	}
	if len(fetchResults) != 10 {
		t.Fatalf("Expected 10 fetch results, got %d", len(fetchResults))
	}
	t.Log("Initial FETCH verified: 10 messages with correct sequence numbers")

	// Connect second client and expunge messages 3, 5, 7 (remove middle messages)
	t.Log("Connecting second client to expunge messages")
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server for second client: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed for second client: %v", err)
	}

	if _, err := c2.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed for second client: %v", err)
	}

	// Mark messages by UID (more reliable than sequence numbers across sessions)
	targetUIDs := []imap.UID{uids[2], uids[4], uids[6]} // UIDs 3, 5, 7
	t.Logf("Marking UIDs %v as deleted", targetUIDs)

	if err := c2.Store(imap.UIDSetNum(targetUIDs...), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		t.Fatalf("STORE \\Deleted flag failed: %v", err)
	}

	// Expunge via second client
	if err := c2.Expunge().Close(); err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}
	t.Log("EXPUNGE completed in second session")

	// Now first client triggers a poll to learn about the expunge
	t.Log("Triggering NOOP in first client to poll for updates")
	if err := c1.Noop().Wait(); err != nil {
		t.Fatalf("NOOP failed: %v", err)
	}

	// After expunge, we should have 7 messages remaining
	// Original: 1,2,3,4,5,6,7,8,9,10
	// Removed:  3,5,7
	// Remaining: 1,2,4,6,8,9,10 with UIDs: uids[0],uids[1],uids[3],uids[5],uids[7],uids[8],uids[9]
	// Database should renumber to sequences: 1,2,3,4,5,6,7

	expectedRemaining := []imap.UID{uids[0], uids[1], uids[3], uids[5], uids[7], uids[8], uids[9]}

	// THIS IS THE CRITICAL TEST: Fetch by sequence number after external expunge
	// Before the fix, this would return wrong sequence numbers due to EncodeSeqNum bug
	t.Log("Fetching sequences 1-7 after expunge (critical test)")
	seqSet = imap.SeqSet{}
	seqSet.AddRange(1, 7)
	fetchResults, err = c1.Fetch(seqSet, &imap.FetchOptions{UID: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH after expunge failed: %v", err)
	}

	if len(fetchResults) != 7 {
		t.Errorf("Expected 7 fetch results after expunge, got %d", len(fetchResults))
	}

	// Verify each message has correct sequence number and UID
	for i, result := range fetchResults {
		expectedSeq := uint32(i + 1) // Should be 1, 2, 3, 4, 5, 6, 7
		expectedUID := expectedRemaining[i]

		if result.SeqNum != expectedSeq {
			t.Errorf("Message %d: expected sequence %d, got %d", i, expectedSeq, result.SeqNum)
		}
		if result.UID != expectedUID {
			t.Errorf("Message %d: expected UID %d, got %d", i, expectedUID, result.UID)
		}
	}

	t.Log("FETCH after expunge verified: all sequence numbers correct")

	// Also test UID FETCH to ensure UIDs are returned correctly
	t.Logf("Testing UID FETCH for specific UID %d", expectedRemaining[3])
	uidFetchResults, err := c1.Fetch(imap.UIDSetNum(expectedRemaining[3]), &imap.FetchOptions{
		UID:      true,
		Envelope: true,
	}).Collect()
	if err != nil {
		t.Fatalf("UID FETCH failed: %v", err)
	}

	if len(uidFetchResults) != 1 {
		t.Fatalf("Expected 1 UID FETCH result, got %d", len(uidFetchResults))
	}

	if uidFetchResults[0].UID != expectedRemaining[3] {
		t.Errorf("UID FETCH returned wrong UID: expected %d, got %d",
			expectedRemaining[3], uidFetchResults[0].UID)
	}

	// The sequence number should be 4 (the 4th remaining message)
	if uidFetchResults[0].SeqNum != 4 {
		t.Errorf("UID FETCH returned wrong sequence: expected 4, got %d", uidFetchResults[0].SeqNum)
	}

	t.Log("UID FETCH verified: correct UID and sequence number returned")
}

// TestIMAP_SequenceNumberConsistency_SearchAfterExternalExpunge tests that
// SEARCH returns correct sequence numbers after messages are expunged externally.
func TestIMAP_SequenceNumberConsistency_SearchAfterExternalExpunge(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Connect first client
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial IMAP server: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if _, err := c1.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Add 20 test messages
	t.Log("Adding 20 messages to mailbox")
	var uids []imap.UID
	for i := 1; i <= 20; i++ {
		testMessage := fmt.Sprintf("From: test@example.com\r\n"+
			"To: %s\r\n"+
			"Subject: Search Test %d\r\n"+
			"Date: %s\r\n"+
			"\r\n"+
			"Message body %d.\r\n", account.Email, i, time.Now().Format(time.RFC1123Z), i)

		appendCmd := c1.Append("INBOX", int64(len(testMessage)), nil)
		if _, err = appendCmd.Write([]byte(testMessage)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err = appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		appendData, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
		uids = append(uids, appendData.UID)
	}

	t.Logf("Added 20 messages with UIDs: %v", uids)

	// Initial SEARCH ALL should return sequences 1-20
	searchResults, err := c1.Search(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("Initial SEARCH failed: %v", err)
	}

	initialSeqs := searchResults.AllSeqNums()
	if len(initialSeqs) != 20 {
		t.Fatalf("Expected 20 search results, got %d", len(initialSeqs))
	}

	// Verify sequence numbers are 1-20
	for i, seq := range initialSeqs {
		if seq != uint32(i+1) {
			t.Errorf("Initial SEARCH: expected sequence %d, got %d", i+1, seq)
		}
	}
	t.Log("Initial SEARCH ALL verified: sequences 1-20")

	// Connect second client and expunge first 10 messages
	t.Log("Connecting second client to expunge first 10 messages")
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial second client: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed for second client: %v", err)
	}

	if _, err := c2.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed for second client: %v", err)
	}

	// Mark first 10 messages as deleted by UID
	firstTenUIDs := uids[0:10]
	t.Logf("Marking first 10 messages (UIDs %v) as deleted", firstTenUIDs)
	if err := c2.Store(imap.UIDSetNum(firstTenUIDs...), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Close(); err != nil {
		t.Fatalf("STORE \\Deleted failed: %v", err)
	}

	if err := c2.Expunge().Close(); err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}
	t.Log("EXPUNGE completed, 10 messages removed")

	// Trigger poll in first client
	t.Log("Triggering NOOP in first client")
	if err := c1.Noop().Wait(); err != nil {
		t.Fatalf("NOOP failed: %v", err)
	}

	// After expunge, we should have 10 messages remaining (originally 11-20)
	// Database should renumber to sequences 1-10
	// Before the fix, SEARCH would return sequences 11-20 (wrong!)

	// THIS IS THE CRITICAL TEST: SEARCH ALL after external expunge
	t.Log("Executing SEARCH ALL after expunge (critical test)")
	searchResults, err = c1.Search(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH after expunge failed: %v", err)
	}

	afterSeqs := searchResults.AllSeqNums()
	if len(afterSeqs) != 10 {
		t.Errorf("Expected 10 search results after expunge, got %d", len(afterSeqs))
	}

	// Verify sequence numbers are 1-10 (not 11-20!)
	for i, seq := range afterSeqs {
		expectedSeq := uint32(i + 1) // Should be 1, 2, 3, ..., 10
		if seq != expectedSeq {
			t.Errorf("SEARCH after expunge: expected sequence %d, got %d", expectedSeq, seq)
		}
	}

	t.Log("SEARCH ALL after expunge verified: sequences 1-10 (correct)")

	// Also test UID SEARCH to ensure UIDs are correct
	t.Log("Testing UID SEARCH ALL")
	uidSearchResults, err := c1.UIDSearch(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("UID SEARCH failed: %v", err)
	}

	resultUIDs := uidSearchResults.AllUIDs()
	if len(resultUIDs) != 10 {
		t.Errorf("Expected 10 UIDs in UID SEARCH, got %d", len(resultUIDs))
	}

	// Verify UIDs match the last 10 original messages
	expectedUIDs := uids[10:20]
	for i, uid := range resultUIDs {
		if uid != expectedUIDs[i] {
			t.Errorf("UID SEARCH: expected UID %d, got %d", expectedUIDs[i], uid)
		}
	}

	t.Log("UID SEARCH ALL verified: correct UIDs returned")
}

// TestIMAP_SequenceNumberConsistency_LargeMailbox tests with a larger mailbox
// to ensure the fix works at scale (reproduces the production bug scenario)
func TestIMAP_SequenceNumberConsistency_LargeMailbox(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large mailbox test in short mode")
	}

	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login failed: %v", err)
	}

	if _, err := c1.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select failed: %v", err)
	}

	// Create 30 messages (enough to expose the bug, but faster)
	t.Log("Creating 30 messages (this may take a moment)")
	messageCount := 30
	for i := 1; i <= messageCount; i++ {
		msg := fmt.Sprintf("Subject: msg%d\r\n\r\nbody%d", i, i)
		appendCmd := c1.Append("INBOX", int64(len(msg)), nil)
		if _, err := appendCmd.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}

		if i%20 == 0 {
			t.Logf("Progress: %d/%d messages created", i, messageCount)
		}
	}

	t.Logf("Created %d messages", messageCount)

	// Directly delete messages from database (simulate many past expunges)
	// Delete messages 10-20 (11 messages)
	ctx := context.Background()
	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatalf("Failed to get mailbox: %v", err)
	}

	t.Log("Directly deleting messages 10-20 from database")
	_, err = server.ResilientDB.GetDatabase().GetWritePool().Exec(ctx,
		"DELETE FROM messages WHERE mailbox_id = $1 AND uid >= 10 AND uid <= 20",
		mailbox.ID)
	if err != nil {
		t.Fatalf("Failed to delete messages: %v", err)
	}

	// The server will disconnect c1 due to severe state desync (expected behavior)
	// Reconnect with a fresh session that will see the correct state
	t.Log("Reconnecting after database manipulation")
	c1.Close() // Close the old connection

	c1, err = imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to reconnect: %v", err)
	}
	defer c1.Logout()

	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Login after reconnect failed: %v", err)
	}

	if _, err := c1.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select after reconnect failed: %v", err)
	}

	// Should have 19 messages remaining: 1-9, 21-30
	// Database sequences should be: 1-19

	// Test SEARCH ALL
	searchResults, err := c1.Search(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH failed: %v", err)
	}

	seqs := searchResults.AllSeqNums()
	if len(seqs) != 19 {
		t.Errorf("Expected 19 search results, got %d", len(seqs))
	}

	// Verify sequences are 1-19 (not some other range!)
	for i, seq := range seqs {
		if seq != uint32(i+1) {
			t.Errorf("Sequence mismatch at index %d: expected %d, got %d", i, i+1, seq)
		}
	}

	t.Log("Large mailbox SEARCH verified: sequences 1-19")

	// Test FETCH on a specific message
	fetchResults, err := c1.Fetch(imap.SeqSetNum(15), &imap.FetchOptions{
		UID: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}

	if len(fetchResults) != 1 {
		t.Fatalf("Expected 1 fetch result, got %d", len(fetchResults))
	}

	// Sequence 15 should correspond to UID 26 (the 15th remaining message)
	// Messages: 1-9 (9 msgs), then 21-30 (10 msgs), so 15th is 9+6=15, which is UID 26
	if fetchResults[0].SeqNum != 15 {
		t.Errorf("Expected sequence 15, got %d", fetchResults[0].SeqNum)
	}

	// UID should be 26 (9 messages 1-9, then 21-26 is the 15th message)
	expectedUID := imap.UID(26)
	if fetchResults[0].UID != expectedUID {
		t.Errorf("Expected UID %d, got %d", expectedUID, fetchResults[0].UID)
	}

	t.Log("Large mailbox FETCH verified: correct sequence and UID mapping")
}
