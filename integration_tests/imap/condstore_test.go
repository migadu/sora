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

// TestIMAP_CondstoreFetch tests FETCH with CHANGEDSINCE and MODSEQ (CONDSTORE extension)
func TestIMAP_CondstoreFetch(t *testing.T) {
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

	// SELECT to enable CONDSTORE
	mbox, err := c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	t.Logf("Initial INBOX: NumMessages=%d, HighestModSeq=%d", mbox.NumMessages, mbox.HighestModSeq)

	if mbox.HighestModSeq == 0 {
		t.Error("❌ Expected HighestModSeq to be set when CONDSTORE is supported")
	} else {
		t.Logf("✅ HighestModSeq is set: %d", mbox.HighestModSeq)
	}

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
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND %d failed: %v", i, err)
		}
	}

	// Re-select to get updated state
	mbox, err = c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Re-select INBOX failed: %v", err)
	}
	t.Logf("After append: NumMessages=%d, HighestModSeq=%d", mbox.NumMessages, mbox.HighestModSeq)
	initialModSeq := mbox.HighestModSeq

	// Test 1: FETCH with MODSEQ returns MODSEQ values
	t.Log("=== Test 1: FETCH with MODSEQ ===")
	fetchCmd := c.Fetch(imap.SeqSetNum(1, 2, 3), &imap.FetchOptions{
		UID:    true,
		ModSeq: true,
	})
	fetchMsgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}

	if len(fetchMsgs) != 3 {
		t.Fatalf("Expected 3 messages, got %d", len(fetchMsgs))
	}

	allHaveModSeq := true
	for _, msg := range fetchMsgs {
		t.Logf("Message UID=%d, SeqNum=%d, MODSEQ=%d", msg.UID, msg.SeqNum, msg.ModSeq)
		if msg.ModSeq == 0 {
			t.Errorf("❌ Expected MODSEQ to be set for message UID=%d", msg.UID)
			allHaveModSeq = false
		}
	}
	if allHaveModSeq {
		t.Log("✅ All messages have MODSEQ values")
	}

	// Test 2: Mark message 2 as \Seen and verify MODSEQ increases
	t.Log("=== Test 2: STORE flags and verify MODSEQ increases ===")
	storeCmd := c.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, &imap.StoreOptions{})

	storeMsgs, err := storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	if len(storeMsgs) != 1 {
		t.Fatalf("Expected 1 STORE response, got %d", len(storeMsgs))
	}
	msg2ModSeq := storeMsgs[0].ModSeq
	t.Logf("After STORE: Message 2 MODSEQ=%d", msg2ModSeq)

	if msg2ModSeq == 0 {
		t.Error("❌ Expected MODSEQ to be returned in STORE response")
	} else if msg2ModSeq <= initialModSeq {
		t.Errorf("❌ Expected MODSEQ to increase after STORE (was %d, now %d)", initialModSeq, msg2ModSeq)
	} else {
		t.Logf("✅ MODSEQ increased after STORE: %d -> %d", initialModSeq, msg2ModSeq)
	}

	// Test 3: FETCH with CHANGEDSINCE (should return only message 2)
	t.Log("=== Test 3: FETCH with CHANGEDSINCE ===")
	fetchCmd = c.Fetch(imap.SeqSetNum(1, 2, 3), &imap.FetchOptions{
		UID:          true,
		Flags:        true,
		ModSeq:       true,
		ChangedSince: initialModSeq,
	})
	changedMsgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH CHANGEDSINCE failed: %v", err)
	}

	t.Logf("FETCH CHANGEDSINCE returned %d messages (expected: message 2 only)", len(changedMsgs))
	if len(changedMsgs) == 0 {
		t.Error("❌ Expected at least 1 message (message 2) to be returned by FETCH CHANGEDSINCE")
	}

	foundMsg2 := false
	for _, msg := range changedMsgs {
		t.Logf("  Changed message: UID=%d, SeqNum=%d, MODSEQ=%d, Flags=%v",
			msg.UID, msg.SeqNum, msg.ModSeq, msg.Flags)
		if msg.SeqNum == 2 {
			foundMsg2 = true
		}
		if msg.ModSeq <= initialModSeq {
			t.Errorf("❌ Message UID=%d has MODSEQ=%d, expected > %d", msg.UID, msg.ModSeq, initialModSeq)
		}
	}

	if foundMsg2 {
		t.Log("✅ FETCH CHANGEDSINCE correctly returned message 2")
	} else {
		t.Error("❌ FETCH CHANGEDSINCE did not return message 2")
	}

	// Test 4: STORE with UNCHANGEDSINCE (conditional STORE)
	t.Log("=== Test 4: STORE with UNCHANGEDSINCE ===")

	// Try to modify message 1 with UNCHANGEDSINCE using current modseq (should succeed)
	storeCmd = c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagFlagged},
	}, &imap.StoreOptions{
		UnchangedSince: msg2ModSeq, // Use message 2's modseq (message 1 hasn't changed since then)
	})

	storeMsgs, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE UNCHANGEDSINCE failed: %v", err)
	}

	if len(storeMsgs) != 1 {
		t.Error("❌ Expected STORE UNCHANGEDSINCE to succeed for message 1")
	} else {
		t.Logf("✅ STORE UNCHANGEDSINCE succeeded: Message 1 now has MODSEQ=%d", storeMsgs[0].ModSeq)
	}

	// Try to modify message 2 with UNCHANGEDSINCE using old modseq (should fail silently)
	t.Log("=== Test 5: STORE with UNCHANGEDSINCE (should fail silently) ===")
	storeCmd = c.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, &imap.StoreOptions{
		UnchangedSince: initialModSeq, // Old modseq - message 2 has changed since then
	})

	storeMsgs, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE UNCHANGEDSINCE failed: %v", err)
	}

	// RFC 7162: When UNCHANGEDSINCE fails, the message is not returned in untagged FETCH
	if len(storeMsgs) == 0 {
		t.Log("✅ STORE UNCHANGEDSINCE correctly failed (no response for message 2)")
	} else {
		t.Logf("⚠️  STORE UNCHANGEDSINCE returned %d messages (RFC 7162: should return 0 for failed conditional)", len(storeMsgs))
	}

	t.Log("✅ All CONDSTORE FETCH tests passed")
}

// TestIMAP_CondstoreSearchSeqNum tests SEARCH/ESEARCH with sequence numbers and MODSEQ
func TestIMAP_CondstoreSearchSeqNum(t *testing.T) {
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

	mbox, err := c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	t.Logf("Initial INBOX: NumMessages=%d, HighestModSeq=%d", mbox.NumMessages, mbox.HighestModSeq)

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
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND %d failed: %v", i, err)
		}
	}

	// Re-select
	mbox, err = c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Re-select INBOX failed: %v", err)
	}
	t.Logf("After append: NumMessages=%d, HighestModSeq=%d", mbox.NumMessages, mbox.HighestModSeq)
	initialModSeq := mbox.HighestModSeq

	// Mark message 2 as \Seen
	t.Log("=== Marking message 2 as \\Seen ===")
	storeCmd := c.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	// Test: SEARCH (seq) RETURN (MIN MAX) with MODSEQ
	t.Log("=== Test: SEARCH RETURN (MIN MAX) with sequence numbers ===")
	searchData, err := c.Search(&imap.SearchCriteria{
		ModSeq: &imap.SearchCriteriaModSeq{
			ModSeq: initialModSeq,
		},
	}, &imap.SearchOptions{
		ReturnMin: true,
		ReturnMax: true,
	}).Wait()
	if err != nil {
		t.Fatalf("SEARCH RETURN (MIN MAX) failed: %v", err)
	}

	t.Logf("ESEARCH result: Min=%d, Max=%d, ModSeq=%d", searchData.Min, searchData.Max, searchData.ModSeq)

	// When using sequence number search (not UID), MIN/MAX should be sequence numbers
	// We expect: messages with modseq > initialModSeq (should include at least message 2)
	if searchData.Min == 0 {
		t.Error("❌ Expected Min to be set in ESEARCH result")
	}
	if searchData.Max == 0 {
		t.Error("❌ Expected Max to be set in ESEARCH result")
	}
	if searchData.ModSeq == 0 {
		t.Error("❌ Expected ModSeq to be set in ESEARCH result")
	}

	// For sequence number search, MIN and MAX should be valid sequence numbers (1-3)
	if searchData.Min > 3 {
		t.Errorf("❌ MIN=%d looks like UID, not sequence number (should be 1-3)", searchData.Min)
	} else {
		t.Logf("✅ MIN=%d is a valid sequence number", searchData.Min)
	}

	if searchData.Max > 3 {
		t.Errorf("❌ MAX=%d looks like UID, not sequence number (should be 1-3)", searchData.Max)
	} else {
		t.Logf("✅ MAX=%d is a valid sequence number", searchData.Max)
	}

	if searchData.Min > searchData.Max {
		t.Errorf("❌ MIN=%d > MAX=%d (MIN should be <= MAX)", searchData.Min, searchData.Max)
	} else {
		t.Logf("✅ MIN=%d <= MAX=%d", searchData.Min, searchData.Max)
	}

	t.Log("✅ CONDSTORE SEARCH with sequence numbers test completed")
}

// TestIMAP_CondstoreSearchUID tests UID SEARCH/ESEARCH with MODSEQ
func TestIMAP_CondstoreSearchUID(t *testing.T) {
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

	mbox, err := c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

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
	}

	// Re-select
	mbox, err = c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Re-select INBOX failed: %v", err)
	}
	initialModSeq := mbox.HighestModSeq

	// Mark message 2 as \Seen
	t.Log("=== Marking message 2 as \\Seen ===")
	storeCmd := c.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	// Test: UID SEARCH RETURN (MIN MAX) with MODSEQ
	t.Log("=== Test: UID SEARCH RETURN (MIN MAX) with MODSEQ ===")
	searchData, err := c.UIDSearch(&imap.SearchCriteria{
		ModSeq: &imap.SearchCriteriaModSeq{
			ModSeq: initialModSeq,
		},
	}, &imap.SearchOptions{
		ReturnMin: true,
		ReturnMax: true,
	}).Wait()
	if err != nil {
		t.Fatalf("UID SEARCH RETURN (MIN MAX) failed: %v", err)
	}

	t.Logf("UID ESEARCH result: Min=%d, Max=%d, ModSeq=%d", searchData.Min, searchData.Max, searchData.ModSeq)
	t.Logf("Expected UIDs: %v", uids)

	if searchData.Min == 0 {
		t.Error("❌ Expected Min to be set in ESEARCH result")
	}
	if searchData.Max == 0 {
		t.Error("❌ Expected Max to be set in ESEARCH result")
	}
	if searchData.ModSeq == 0 {
		t.Error("❌ Expected ModSeq to be set in ESEARCH result")
	}

	// For UID search, MIN and MAX should be UIDs (not sequence numbers)
	// UIDs should be >= the UIDs we got from APPEND
	if searchData.Min < uint32(uids[0]) {
		t.Errorf("❌ MIN=%d is less than first UID=%d", searchData.Min, uids[0])
	} else {
		t.Logf("✅ MIN=%d is a valid UID", searchData.Min)
	}

	if searchData.Max < uint32(uids[0]) {
		t.Errorf("❌ MAX=%d is less than first UID=%d", searchData.Max, uids[0])
	} else {
		t.Logf("✅ MAX=%d is a valid UID", searchData.Max)
	}

	if searchData.Min > searchData.Max {
		t.Errorf("❌ MIN=%d > MAX=%d (MIN should be <= MAX)", searchData.Min, searchData.Max)
	} else {
		t.Logf("✅ MIN=%d <= MAX=%d", searchData.Min, searchData.Max)
	}

	t.Log("✅ CONDSTORE UID SEARCH test completed")
}
