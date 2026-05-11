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

// TestIMAP_QResyncSelectBasic tests basic QRESYNC SELECT functionality
// RFC 7162 §3.2.5: SELECT with QRESYNC parameter
func TestIMAP_QResyncSelectBasic(t *testing.T) {
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

	// RFC 7162 §3.1: QRESYNC must be explicitly enabled with ENABLE command
	t.Log("Testing QRESYNC support...")
	enableCmd := c.Enable(imap.CapQResync)
	enableData, err := enableCmd.Wait()
	if err != nil {
		t.Fatalf("ENABLE QRESYNC failed: %v", err)
	}
	if !enableData.Caps.Has(imap.CapQResync) {
		t.Fatal("Server did not enable QRESYNC capability")
	}
	t.Log("✅ QRESYNC enabled")

	// Initial SELECT to get baseline state
	t.Log("=== Initial SELECT ===")
	mbox, err := c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Initial SELECT failed: %v", err)
	}
	t.Logf("Initial state: UIDValidity=%d, HighestModSeq=%d, NumMessages=%d",
		mbox.UIDValidity, mbox.HighestModSeq, mbox.NumMessages)

	initialUIDValidity := mbox.UIDValidity
	initialModSeq := mbox.HighestModSeq

	if initialModSeq == 0 {
		t.Fatal("❌ HighestModSeq is 0, CONDSTORE not working")
	}

	// Append 5 messages
	t.Log("=== Appending 5 messages ===")
	var uids []imap.UID
	for i := 1; i <= 5; i++ {
		msg := fmt.Sprintf("From: sender@example.com\r\n"+
			"To: %s\r\n"+
			"Subject: Test Message %d\r\n"+
			"Date: %s\r\n"+
			"\r\n"+
			"This is test message number %d\r\n", account.Email, i, time.Now().Format(time.RFC1123Z), i)

		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		appendCmd.Write([]byte(msg))
		appendCmd.Close()
		appendData, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND %d failed: %v", i, err)
		}
		uids = append(uids, appendData.UID)
		t.Logf("  Appended message %d: UID=%d", i, appendData.UID)
	}

	// Re-SELECT to get updated state
	t.Log("=== Re-SELECT to get current state ===")
	mbox, err = c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Re-SELECT failed: %v", err)
	}
	t.Logf("After APPEND: UIDValidity=%d, HighestModSeq=%d, NumMessages=%d",
		mbox.UIDValidity, mbox.HighestModSeq, mbox.NumMessages)

	if mbox.NumMessages != 5 {
		t.Fatalf("Expected 5 messages, got %d", mbox.NumMessages)
	}

	afterAppendModSeq := mbox.HighestModSeq

	// Mark messages 2 and 4 as \Seen
	t.Log("=== Marking messages 2 and 4 as \\Seen ===")
	storeCmd := c.Store(imap.SeqSetNum(2, 4), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	// Expunge message 3
	t.Log("=== Expunging message 3 ===")
	storeCmd = c.Store(imap.SeqSetNum(3), &imap.StoreFlags{
		Op:    imap.StoreFlagsSet,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE \\Deleted failed: %v", err)
	}

	expungeCmd := c.Expunge()
	if err := expungeCmd.Close(); err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}
	t.Logf("  Expunged UID=%d", uids[2])

	// Get current state after changes
	t.Log("=== Re-SELECT to get state after changes ===")
	mbox, err = c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Re-SELECT failed: %v", err)
	}
	t.Logf("After changes: UIDValidity=%d, HighestModSeq=%d, NumMessages=%d",
		mbox.UIDValidity, mbox.HighestModSeq, mbox.NumMessages)

	_ = mbox.HighestModSeq // Will use later for verification

	// Test 1: QRESYNC SELECT with minimal parameters (UIDValidity + ModSeq)
	t.Log("=== Test 1: QRESYNC SELECT (minimal) ===")
	qresyncMbox, err := c.Select("INBOX", &imap.SelectOptions{
		QResync: &imap.QResyncData{
			UIDValidity: initialUIDValidity,
			ModSeq:      afterAppendModSeq, // Sync from after APPEND
		},
	}).Wait()
	if err != nil {
		t.Fatalf("QRESYNC SELECT failed: %v", err)
	}

	t.Logf("QRESYNC SELECT result:")
	t.Logf("  UIDValidity=%d, HighestModSeq=%d, NumMessages=%d",
		qresyncMbox.UIDValidity, qresyncMbox.HighestModSeq, qresyncMbox.NumMessages)
	t.Logf("  Vanished UIDs: %v", qresyncMbox.Vanished)
	t.Logf("  Modified messages: %d", len(qresyncMbox.Modified))

	// Verify VANISHED contains UID 3
	if len(qresyncMbox.Vanished) == 0 {
		t.Error("❌ Expected VANISHED to contain expunged UID 3")
	} else {
		containsUID3 := false
		for _, uidRange := range qresyncMbox.Vanished {
			if uids[2] >= uidRange.Start && uids[2] <= uidRange.Stop {
				containsUID3 = true
				break
			}
		}
		if containsUID3 {
			t.Logf("✅ VANISHED correctly contains expunged UID %d", uids[2])
		} else {
			t.Errorf("❌ VANISHED does not contain expunged UID %d: %v", uids[2], qresyncMbox.Vanished)
		}
	}

	// Verify Modified contains messages 2 and 4 (marked as \Seen)
	if len(qresyncMbox.Modified) < 2 {
		t.Errorf("❌ Expected at least 2 modified messages, got %d", len(qresyncMbox.Modified))
	} else {
		t.Log("✅ QRESYNC SELECT returned modified messages:")
		foundUID2 := false
		foundUID4 := false
		for _, mod := range qresyncMbox.Modified {
			t.Logf("    UID=%d, SeqNum=%d, Flags=%v, ModSeq=%d",
				mod.UID, mod.SeqNum, mod.Flags, mod.ModSeq)
			if mod.UID == uids[1] {
				foundUID2 = true
			}
			if mod.UID == uids[3] {
				foundUID4 = true
			}
			if mod.ModSeq <= afterAppendModSeq {
				t.Errorf("❌ Modified message UID=%d has old ModSeq=%d (expected > %d)",
					mod.UID, mod.ModSeq, afterAppendModSeq)
			}
		}
		if foundUID2 && foundUID4 {
			t.Log("✅ Modified messages include UIDs 2 and 4")
		} else {
			t.Errorf("❌ Modified messages missing: UID2=%v, UID4=%v", foundUID2, foundUID4)
		}
	}

	// Verify HighestModSeq increased
	if qresyncMbox.HighestModSeq <= afterAppendModSeq {
		t.Errorf("❌ HighestModSeq did not increase: was %d, now %d",
			afterAppendModSeq, qresyncMbox.HighestModSeq)
	} else {
		t.Logf("✅ HighestModSeq increased: %d -> %d", afterAppendModSeq, qresyncMbox.HighestModSeq)
	}

	// Verify NumMessages decreased by 1 (one message expunged)
	if qresyncMbox.NumMessages != 4 {
		t.Errorf("❌ NumMessages=%d (expected 4)", qresyncMbox.NumMessages)
	} else {
		t.Log("✅ NumMessages correctly shows 4 (5 - 1 expunged)")
	}

	t.Log("✅ QRESYNC SELECT basic test completed")
}

// TestIMAP_QResyncSelectUIDValidityMismatch tests UIDVALIDITY mismatch handling
// RFC 7162 §3.2.5: Client must resync if UIDVALIDITY changes
func TestIMAP_QResyncSelectUIDValidityMismatch(t *testing.T) {
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

	// RFC 7162 §3.1: QRESYNC must be explicitly enabled with ENABLE command
	t.Log("Testing QRESYNC support...")
	enableCmd := c.Enable(imap.CapQResync)
	enableData, err := enableCmd.Wait()
	if err != nil {
		t.Fatalf("ENABLE QRESYNC failed: %v", err)
	}
	if !enableData.Caps.Has(imap.CapQResync) {
		t.Fatal("Server did not enable QRESYNC capability")
	}
	t.Log("✅ QRESYNC enabled")

	// Initial SELECT
	t.Log("=== Initial SELECT ===")
	mbox, err := c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Initial SELECT failed: %v", err)
	}
	t.Logf("UIDValidity=%d, HighestModSeq=%d", mbox.UIDValidity, mbox.HighestModSeq)

	// Test: QRESYNC SELECT with wrong UIDValidity
	t.Log("=== Test: QRESYNC SELECT with wrong UIDValidity ===")
	wrongUIDValidity := mbox.UIDValidity + 1000
	qresyncMbox, err := c.Select("INBOX", &imap.SelectOptions{
		QResync: &imap.QResyncData{
			UIDValidity: wrongUIDValidity,
			ModSeq:      mbox.HighestModSeq,
		},
	}).Wait()

	// Server should NOT return error - just normal SELECT response
	if err != nil {
		t.Fatalf("QRESYNC SELECT with wrong UIDValidity failed: %v (should succeed)", err)
	}

	t.Logf("Server response: UIDValidity=%d, HighestModSeq=%d",
		qresyncMbox.UIDValidity, qresyncMbox.HighestModSeq)

	// Verify server did NOT send VANISHED (UIDVALIDITY mismatch)
	if len(qresyncMbox.Vanished) > 0 {
		t.Error("❌ Server sent VANISHED despite UIDVALIDITY mismatch (should not)")
	} else {
		t.Log("✅ Server correctly omitted VANISHED for UIDVALIDITY mismatch")
	}

	// Verify server did NOT send Modified messages
	if len(qresyncMbox.Modified) > 0 {
		t.Error("❌ Server sent Modified messages despite UIDVALIDITY mismatch (should not)")
	} else {
		t.Log("✅ Server correctly omitted Modified for UIDVALIDITY mismatch")
	}

	// Verify UIDValidity in response matches actual current UIDValidity
	if qresyncMbox.UIDValidity != mbox.UIDValidity {
		t.Errorf("❌ Response UIDValidity=%d, expected %d",
			qresyncMbox.UIDValidity, mbox.UIDValidity)
	} else {
		t.Logf("✅ Response UIDValidity=%d matches current mailbox", qresyncMbox.UIDValidity)
	}

	t.Log("✅ UIDVALIDITY mismatch test completed")
}

// TestIMAP_FetchVanished tests UID FETCH with VANISHED modifier
// RFC 7162 §3.2.6: UID FETCH with CHANGEDSINCE and VANISHED
func TestIMAP_FetchVanished(t *testing.T) {
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

	// RFC 7162 §3.1: QRESYNC must be explicitly enabled with ENABLE command
	t.Log("Testing QRESYNC support...")
	enableCmd := c.Enable(imap.CapQResync)
	enableData, err := enableCmd.Wait()
	if err != nil {
		t.Fatalf("ENABLE QRESYNC failed: %v", err)
	}
	if !enableData.Caps.Has(imap.CapQResync) {
		t.Fatal("Server did not enable QRESYNC capability")
	}
	t.Log("✅ QRESYNC enabled")

	// Initial SELECT
	t.Log("=== Initial SELECT ===")
	mbox, err := c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Initial SELECT failed: %v", err)
	}
	t.Logf("Initial: HighestModSeq=%d, NumMessages=%d", mbox.HighestModSeq, mbox.NumMessages)

	// Append 5 messages
	t.Log("=== Appending 5 messages ===")
	var uids []imap.UID
	for i := 1; i <= 5; i++ {
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

	// Re-SELECT
	mbox, err = c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Re-SELECT failed: %v", err)
	}
	afterAppendModSeq := mbox.HighestModSeq
	t.Logf("After APPEND: HighestModSeq=%d, NumMessages=%d", mbox.HighestModSeq, mbox.NumMessages)

	// Mark messages 2 and 4 as \Seen
	t.Log("=== Marking messages 2 and 4 as \\Seen ===")
	storeCmd := c.Store(imap.SeqSetNum(2, 4), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	// Expunge messages 1 and 3
	t.Log("=== Expunging messages 1 and 3 ===")
	storeCmd = c.Store(imap.SeqSetNum(1, 3), &imap.StoreFlags{
		Op:    imap.StoreFlagsSet,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE \\Deleted failed: %v", err)
	}

	expungeCmd := c.Expunge()
	if err := expungeCmd.Close(); err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}
	t.Logf("  Expunged UIDs: %d, %d", uids[0], uids[2])

	// Test: UID FETCH with CHANGEDSINCE and VANISHED
	t.Log("=== Test: UID FETCH with CHANGEDSINCE and VANISHED ===")
	uidSet := imap.UIDSet{{Start: uids[0], Stop: uids[4]}}
	fetchCmd := c.Fetch(uidSet, &imap.FetchOptions{
		UID:          true,
		Flags:        true,
		ModSeq:       true,
		ChangedSince: afterAppendModSeq,
		Vanished:     true,
	})

	// Collect FETCH responses
	fetchMsgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("UID FETCH VANISHED failed: %v", err)
	}

	t.Logf("UID FETCH returned %d messages", len(fetchMsgs))
	for _, msg := range fetchMsgs {
		t.Logf("  UID=%d, Flags=%v, ModSeq=%d", msg.UID, msg.Flags, msg.ModSeq)
	}

	// Note: go-imap v2 may not expose VANISHED response directly in FetchMessageData
	// We need to check if there's a way to get the VANISHED response
	// This might require checking unilateral data or extending the client

	// For now, verify we got the changed messages (2 and 4)
	foundUID2 := false
	foundUID4 := false
	for _, msg := range fetchMsgs {
		if msg.UID == uids[1] {
			foundUID2 = true
		}
		if msg.UID == uids[3] {
			foundUID4 = true
		}
		// Should NOT include expunged UIDs 1 and 3
		if msg.UID == uids[0] || msg.UID == uids[2] {
			t.Errorf("❌ FETCH returned expunged UID %d (should not)", msg.UID)
		}
	}

	if foundUID2 && foundUID4 {
		t.Log("✅ FETCH returned modified messages (UIDs 2 and 4)")
	} else {
		t.Errorf("❌ FETCH missing modified messages: UID2=%v, UID4=%v", foundUID2, foundUID4)
	}

	// TODO: Once we can access VANISHED response from go-imap, verify it contains UIDs 1 and 3
	t.Log("⚠️  VANISHED response verification requires go-imap client extension")

	t.Log("✅ FETCH VANISHED test completed")
}

// TestIMAP_QResyncEmptyMailbox tests QRESYNC with empty mailbox
func TestIMAP_QResyncEmptyMailbox(t *testing.T) {
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

	// RFC 7162 §3.1: QRESYNC must be explicitly enabled with ENABLE command
	t.Log("Testing QRESYNC support...")
	enableCmd := c.Enable(imap.CapQResync)
	enableData, err := enableCmd.Wait()
	if err != nil {
		t.Fatalf("ENABLE QRESYNC failed: %v", err)
	}
	if !enableData.Caps.Has(imap.CapQResync) {
		t.Fatal("Server did not enable QRESYNC capability")
	}
	t.Log("✅ QRESYNC enabled")

	// SELECT empty INBOX
	t.Log("=== SELECT empty INBOX ===")
	mbox, err := c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	if mbox.NumMessages != 0 {
		t.Skipf("INBOX not empty (%d messages), skipping test", mbox.NumMessages)
	}

	t.Logf("Empty INBOX: UIDValidity=%d, HighestModSeq=%d", mbox.UIDValidity, mbox.HighestModSeq)

	// Test: QRESYNC SELECT on empty mailbox
	t.Log("=== Test: QRESYNC SELECT on empty mailbox ===")
	qresyncMbox, err := c.Select("INBOX", &imap.SelectOptions{
		QResync: &imap.QResyncData{
			UIDValidity: mbox.UIDValidity,
			ModSeq:      mbox.HighestModSeq,
		},
	}).Wait()
	if err != nil {
		t.Fatalf("QRESYNC SELECT failed: %v", err)
	}

	t.Logf("QRESYNC result: NumMessages=%d, Vanished=%v, Modified=%d",
		qresyncMbox.NumMessages, qresyncMbox.Vanished, len(qresyncMbox.Modified))

	// Verify no VANISHED or Modified
	if len(qresyncMbox.Vanished) > 0 {
		t.Error("❌ VANISHED should be empty for empty mailbox")
	} else {
		t.Log("✅ VANISHED is empty")
	}

	if len(qresyncMbox.Modified) > 0 {
		t.Error("❌ Modified should be empty for empty mailbox")
	} else {
		t.Log("✅ Modified is empty")
	}

	t.Log("✅ QRESYNC empty mailbox test completed")
}

// TestIMAP_QResyncWithKnownUIDs tests QRESYNC with known-uids parameter
// RFC 7162 §3.2.5: Server MAY use known-uids for optimization
func TestIMAP_QResyncWithKnownUIDs(t *testing.T) {
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

	// RFC 7162 §3.1: QRESYNC must be explicitly enabled with ENABLE command
	t.Log("Testing QRESYNC support...")
	enableCmd := c.Enable(imap.CapQResync)
	enableData, err := enableCmd.Wait()
	if err != nil {
		t.Fatalf("ENABLE QRESYNC failed: %v", err)
	}
	if !enableData.Caps.Has(imap.CapQResync) {
		t.Fatal("Server did not enable QRESYNC capability")
	}
	t.Log("✅ QRESYNC enabled")

	// Initial SELECT
	mbox, err := c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}
	initialUIDValidity := mbox.UIDValidity
	_ = mbox.HighestModSeq // Will use for verification

	// Append 3 messages
	t.Log("=== Appending 3 messages ===")
	var uids []imap.UID
	for i := 1; i <= 3; i++ {
		msg := fmt.Sprintf("From: sender@example.com\r\n"+
			"Subject: Test %d\r\n"+
			"\r\n"+
			"Body %d\r\n", i, i)

		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		appendCmd.Write([]byte(msg))
		appendCmd.Close()
		appendData, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
		uids = append(uids, appendData.UID)
	}

	// Re-SELECT
	mbox, err = c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Re-SELECT failed: %v", err)
	}
	afterAppendModSeq := mbox.HighestModSeq

	// Mark message 2 as \Seen
	storeCmd := c.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	// Test: QRESYNC with known-uids
	// RFC 7162 §3.2.5: KnownUIDs is an optional optimization parameter
	t.Log("=== Test: QRESYNC with known-uids ===")
	knownUIDs := imap.UIDSet{
		{Start: uids[0], Stop: uids[2]}, // All UIDs 1-3
	}

	qresyncMbox, err := c.Select("INBOX", &imap.SelectOptions{
		QResync: &imap.QResyncData{
			UIDValidity: initialUIDValidity,
			ModSeq:      afterAppendModSeq,
			KnownUIDs:   knownUIDs,
		},
	}).Wait()
	if err != nil {
		t.Fatalf("QRESYNC with known-uids failed: %v", err)
	}

	t.Logf("QRESYNC result: Modified=%d, Vanished=%v",
		len(qresyncMbox.Modified), qresyncMbox.Vanished)

	// Server MAY optimize based on known-uids, but we just verify it works
	// At minimum, should return modified messages
	if len(qresyncMbox.Modified) == 0 {
		t.Error("❌ Expected modified messages (at least UID 2 with \\Seen)")
	} else {
		t.Logf("✅ QRESYNC with known-uids returned %d modified messages", len(qresyncMbox.Modified))
	}

	t.Log("✅ QRESYNC with known-uids test completed")
}
