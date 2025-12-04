//go:build integration

package imap_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_CondstoreSearch tests SEARCH with MODSEQ criteria (CONDSTORE extension)
func TestIMAP_CondstoreSearch(t *testing.T) {
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

	// SELECT with CONDSTORE to enable CONDSTORE
	selectCmd := c.Select("INBOX", &imap.SelectOptions{})
	mbox, err := selectCmd.Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	t.Logf("Initial INBOX: NumMessages=%d, HighestModSeq=%d", mbox.NumMessages, mbox.HighestModSeq)

	// Append 3 messages
	t.Log("=== Appending 3 messages ===")
	var uids []imap.UID
	for i := 1; i <= 3; i++ {
		msg := fmt.Sprintf("From: sender@example.com\r\n"+
			"To: %s\r\n"+
			"Subject: Test %d\r\n"+
			"Date: %s\r\n"+
			"\r\n"+
			"Message %d\r\n", account.Email, i, time.Now().Format(time.RFC1123Z), i)

		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		appendCmd.Write([]byte(msg))
		appendCmd.Close()
		appendData, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND %d failed: %v", i, err)
		}
		uids = append(uids, appendData.UID)
		t.Logf("Appended message %d: UID=%d", i, appendData.UID)
	}

	// Re-select to get updated state
	mbox, err = c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Re-select INBOX failed: %v", err)
	}
	t.Logf("After append: NumMessages=%d, HighestModSeq=%d", mbox.NumMessages, mbox.HighestModSeq)

	// Mark message 2 as \Seen
	t.Log("=== Marking message 2 as \\Seen ===")
	storeCmd := c.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	// Get MODSEQ of message 2
	fetchCmd := c.Fetch(imap.SeqSetNum(2), &imap.FetchOptions{
		UID:    true,
		ModSeq: true,
	})
	fetchMsgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH MODSEQ failed: %v", err)
	}
	if len(fetchMsgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(fetchMsgs))
	}
	msg2ModSeq := fetchMsgs[0].ModSeq
	t.Logf("Message 2 (UID=%d) has MODSEQ=%d", fetchMsgs[0].UID, msg2ModSeq)

	// Test 1: SEARCH with MODSEQ (should return messages changed since a specific modseq)
	t.Log("=== Test 1: SEARCH MODSEQ ===")
	searchData, err := c.Search(&imap.SearchCriteria{
		ModSeq: &imap.SearchCriteriaModSeq{
			ModSeq: msg2ModSeq - 1, // Search for messages with modseq >= (msg2ModSeq - 1)
		},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH MODSEQ failed: %v", err)
	}

	t.Logf("SEARCH MODSEQ result: All=%v (nil=%v), ModSeq=%d", searchData.All, searchData.All == nil, searchData.ModSeq)

	// We expect at least message 2 to be returned (it was modified)
	if searchData.All == nil {
		t.Error("Expected All to be set in SEARCH result")
	} else {
		t.Logf("SEARCH returned messages: %v", searchData.All)
	}

	// Test 2: ESEARCH with MODSEQ and RETURN (MIN)
	t.Log("=== Test 2: SEARCH RETURN (MIN) with MODSEQ ===")
	searchData, err = c.Search(&imap.SearchCriteria{
		ModSeq: &imap.SearchCriteriaModSeq{
			ModSeq: msg2ModSeq - 1,
		},
	}, &imap.SearchOptions{
		ReturnMin: true,
	}).Wait()
	if err != nil {
		t.Fatalf("SEARCH RETURN (MIN) MODSEQ failed: %v", err)
	}

	t.Logf("ESEARCH RETURN (MIN) result: Min=%d, ModSeq=%d", searchData.Min, searchData.ModSeq)

	if searchData.Min == 0 {
		t.Error("Expected Min to be set in ESEARCH result")
	}
	if searchData.ModSeq == 0 {
		t.Error("Expected ModSeq to be set in ESEARCH result")
	}

	// Test 3: ESEARCH with MODSEQ and RETURN (MAX)
	t.Log("=== Test 3: SEARCH RETURN (MAX) with MODSEQ ===")
	searchData, err = c.Search(&imap.SearchCriteria{
		ModSeq: &imap.SearchCriteriaModSeq{
			ModSeq: msg2ModSeq - 1,
		},
	}, &imap.SearchOptions{
		ReturnMax: true,
	}).Wait()
	if err != nil {
		t.Fatalf("SEARCH RETURN (MAX) MODSEQ failed: %v", err)
	}

	t.Logf("ESEARCH RETURN (MAX) result: Max=%d, ModSeq=%d", searchData.Max, searchData.ModSeq)

	if searchData.Max == 0 {
		t.Error("Expected Max to be set in ESEARCH result")
	}
	if searchData.ModSeq == 0 {
		t.Error("Expected ModSeq to be set in ESEARCH result")
	}

	// Test 4: ESEARCH with MODSEQ and RETURN (MIN MAX)
	t.Log("=== Test 4: SEARCH RETURN (MIN MAX) with MODSEQ ===")
	searchData, err = c.Search(&imap.SearchCriteria{
		ModSeq: &imap.SearchCriteriaModSeq{
			ModSeq: msg2ModSeq - 1,
		},
	}, &imap.SearchOptions{
		ReturnMin: true,
		ReturnMax: true,
	}).Wait()
	if err != nil {
		t.Fatalf("SEARCH RETURN (MIN MAX) MODSEQ failed: %v", err)
	}

	t.Logf("ESEARCH RETURN (MIN MAX) result: Min=%d, Max=%d, ModSeq=%d",
		searchData.Min, searchData.Max, searchData.ModSeq)

	if searchData.Min == 0 {
		t.Error("Expected Min to be set in ESEARCH result")
	}
	if searchData.Max == 0 {
		t.Error("Expected Max to be set in ESEARCH result")
	}
	if searchData.ModSeq == 0 {
		t.Error("Expected ModSeq to be set in ESEARCH result")
	}

	t.Log("✅ All CONDSTORE SEARCH tests passed")
}

// TestIMAP_CondstoreSearchFiltering tests that SEARCH with MODSEQ actually filters messages
func TestIMAP_CondstoreSearchFiltering(t *testing.T) {
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

	// SELECT with CONDSTORE to enable CONDSTORE
	mbox, err := c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	initialModSeq := mbox.HighestModSeq
	t.Logf("Initial INBOX: NumMessages=%d, HighestModSeq=%d", mbox.NumMessages, initialModSeq)

	// Append 3 messages
	t.Log("=== Appending 3 messages ===")
	for i := 1; i <= 3; i++ {
		msg := fmt.Sprintf("From: sender@example.com\r\n"+
			"To: %s\r\n"+
			"Subject: Test %d\r\n"+
			"Date: %s\r\n"+
			"\r\n"+
			"Message %d\r\n", account.Email, i, time.Now().Format(time.RFC1123Z), i)

		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		appendCmd.Write([]byte(msg))
		appendCmd.Close()
		appendData, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND %d failed: %v", i, err)
		}
		t.Logf("Appended message %d: UID=%d", i, appendData.UID)
	}

	// Get MODSEQ values for all messages
	t.Log("=== Fetching initial MODSEQ values ===")
	fetchCmd := c.Fetch(imap.SeqSetNum(1, 2, 3), &imap.FetchOptions{
		UID:    true,
		ModSeq: true,
	})
	fetchMsgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH MODSEQ failed: %v", err)
	}
	if len(fetchMsgs) != 3 {
		t.Fatalf("Expected 3 messages, got %d", len(fetchMsgs))
	}

	var modseqs []uint64
	for _, msg := range fetchMsgs {
		t.Logf("Message UID=%d, SeqNum=%d, MODSEQ=%d", msg.UID, msg.SeqNum, msg.ModSeq)
		modseqs = append(modseqs, msg.ModSeq)
	}

	// Mark message 2 as \Seen (this will increase its MODSEQ)
	t.Log("=== Marking message 2 as \\Seen ===")
	storeCmd := c.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	// Get updated MODSEQ for message 2
	fetchCmd = c.Fetch(imap.SeqSetNum(2), &imap.FetchOptions{
		UID:    true,
		ModSeq: true,
	})
	fetchMsgs, err = fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH MODSEQ failed: %v", err)
	}
	if len(fetchMsgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(fetchMsgs))
	}
	msg2NewModSeq := fetchMsgs[0].ModSeq
	t.Logf("Message 2 updated: UID=%d, MODSEQ=%d (was %d)", fetchMsgs[0].UID, msg2NewModSeq, modseqs[1])

	// TEST: SEARCH with MODSEQ should only return message 2 (the one that was modified)
	t.Log("=== TEST: SEARCH MODSEQ (should filter messages) ===")

	// Search for messages with MODSEQ >= msg2NewModSeq
	// This should return ONLY message 2, not all 3 messages
	searchData, err := c.Search(&imap.SearchCriteria{
		ModSeq: &imap.SearchCriteriaModSeq{
			ModSeq: msg2NewModSeq,
		},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH MODSEQ failed: %v", err)
	}

	t.Logf("SEARCH MODSEQ >= %d result: All=%v, ModSeq=%d", msg2NewModSeq, searchData.All, searchData.ModSeq)

	// Verify: Should return ONLY message 2 (sequence number 2)
	seqNums := searchData.AllSeqNums()
	t.Logf("Messages returned: %v (count: %d)", seqNums, len(seqNums))

	if len(seqNums) != 1 {
		t.Errorf("Expected SEARCH to return 1 message (only msg 2 was modified), got %d messages: %v",
			len(seqNums), seqNums)
		t.Errorf("MODSEQ filtering is NOT working - all messages returned instead of only modified ones")
	} else if seqNums[0] != 2 {
		t.Errorf("Expected SEARCH to return message 2 (seqnum=2), got seqnum=%d", seqNums[0])
	} else {
		t.Log("✅ MODSEQ filtering works correctly - only message 2 returned")
	}

	// TEST 2: Search with very high MODSEQ should return nothing
	t.Log("=== TEST: SEARCH MODSEQ (very high value - should return nothing) ===")
	searchData, err = c.Search(&imap.SearchCriteria{
		ModSeq: &imap.SearchCriteriaModSeq{
			ModSeq: msg2NewModSeq + 1000,
		},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH MODSEQ failed: %v", err)
	}

	t.Logf("SEARCH MODSEQ >= %d result: All=%v, ModSeq=%d", msg2NewModSeq+1000, searchData.All, searchData.ModSeq)

	seqNums2 := searchData.AllSeqNums()
	if len(seqNums2) > 0 {
		t.Errorf("Expected SEARCH with high MODSEQ to return nothing, got %d messages: %v", len(seqNums2), seqNums2)
	} else {
		t.Log("✅ MODSEQ filtering works - no messages returned for high MODSEQ threshold")
	}

	t.Log("✅ All CONDSTORE SEARCH filtering tests completed")
}
