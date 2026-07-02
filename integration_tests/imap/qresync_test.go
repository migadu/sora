//go:build integration

package imap_test

import (
	"fmt"
	"sync"
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

	// Live VANISHED responses (RFC 7162 §3.2.10) — the non-EARLIER kind emitted
	// during a UID FETCH — are delivered through the unilateral data handler, not
	// through fetchCmd.Collect(). Register a handler to capture them for assertion.
	var (
		vanishedMu   sync.Mutex
		vanishedUIDs imap.UIDSet
	)
	c, err := imapclient.DialInsecure(server.Address, &imapclient.Options{
		UnilateralDataHandler: &imapclient.UnilateralDataHandler{
			Vanished: func(data *imap.VanishedData) {
				vanishedMu.Lock()
				vanishedUIDs = append(vanishedUIDs, data.UIDs...)
				vanishedMu.Unlock()
			},
		},
	})
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

	// Verify the VANISHED response captured by the unilateral handler reports the
	// expunged UIDs 1 and 3 (RFC 7162 §3.2.6). fetchCmd.Collect() only returns
	// live messages; VANISHED arrives out-of-band via the handler registered above.
	vanishedMu.Lock()
	gotVanished := vanishedUIDs
	vanishedMu.Unlock()

	t.Logf("VANISHED reported UIDs: %v", gotVanished)
	if !gotVanished.Contains(uids[0]) {
		t.Errorf("❌ VANISHED missing expunged UID %d", uids[0])
	}
	if !gotVanished.Contains(uids[2]) {
		t.Errorf("❌ VANISHED missing expunged UID %d", uids[2])
	}
	// The modified-but-live UIDs must NOT appear in VANISHED.
	if gotVanished.Contains(uids[1]) || gotVanished.Contains(uids[3]) {
		t.Errorf("❌ VANISHED wrongly reported a live UID: %v", gotVanished)
	}
	if gotVanished.Contains(uids[0]) && gotVanished.Contains(uids[2]) {
		t.Log("✅ VANISHED reported expunged UIDs 1 and 3")
	}

	t.Log("✅ FETCH VANISHED test completed")
}

// TestIMAP_QResyncSequenceNumberStaleness validates that QRESYNC Modified responses
// contain sequence numbers based on CURRENT mailbox state (not historical state).
// This is the CORRECT behavior per RFC 7162 §3.2.5.
//
// Test scenario:
// 1. Client syncs at modseq 1636 with messages [1,2,3,4,5] at seqnums [1,2,3,4,5]
// 2. Message 3 gets flag change at modseq 1637
// 3. Message 1 gets expunged at modseq 1639
// 4. Client QRESYNCs with modseq 1636 (their last known state)
// 5. Server returns:
//   - VANISHED: UID 1 (tells client to remove UID 1 from cache)
//   - Modified: UID 3, seqnum 2 (CURRENT state after expunge)
//
// 6. Client processes VANISHED first → removes UID 1 → shifts seqnums down
// 7. Client processes Modified → UID 3 at seqnum 2 matches their updated cache
// 8. Result: NO stuttering, cache stays synchronized
//
// This test validates that sequence numbers reflect CURRENT state, which combined
// with accurate VANISHED responses (via set subtraction), prevents Apple Mail stuttering.
func TestIMAP_QResyncSequenceNumberStaleness(t *testing.T) {
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

	// Enable QRESYNC
	t.Log("=== Enabling QRESYNC ===")
	enableCmd := c.Enable(imap.CapQResync)
	enableData, err := enableCmd.Wait()
	if err != nil {
		t.Fatalf("ENABLE QRESYNC failed: %v", err)
	}
	if !enableData.Caps.Has(imap.CapQResync) {
		t.Fatal("Server did not enable QRESYNC capability")
	}

	// Initial SELECT
	mbox, err := c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("Initial SELECT failed: %v", err)
	}
	t.Logf("Initial: UIDValidity=%d, HighestModSeq=%d", mbox.UIDValidity, mbox.HighestModSeq)

	initialUIDValidity := mbox.UIDValidity

	// Step 1: Append 5 messages to establish baseline
	t.Log("=== Step 1: Appending 5 messages ===")
	var uids []imap.UID
	for i := 1; i <= 5; i++ {
		msg := fmt.Sprintf("From: sender@example.com\r\n"+
			"To: %s\r\n"+
			"Subject: Message %d\r\n"+
			"Date: %s\r\n"+
			"\r\n"+
			"Body %d\r\n", account.Email, i, time.Now().Format(time.RFC1123Z), i)

		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		appendCmd.Write([]byte(msg))
		appendCmd.Close()
		appendData, err := appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND %d failed: %v", i, err)
		}
		uids = append(uids, appendData.UID)
		t.Logf("  Appended UID %d (will be seqnum %d)", appendData.UID, i)
	}

	// Step 2: SELECT to get baseline state (simulate client's last sync)
	t.Log("=== Step 2: SELECT to capture baseline state (client's last sync) ===")
	mbox, err = c.Select("INBOX", &imap.SelectOptions{}).Wait()
	if err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}
	clientLastModSeq := mbox.HighestModSeq
	t.Logf("Client's last sync: ModSeq=%d, Messages=%d", clientLastModSeq, mbox.NumMessages)
	t.Logf("  Expected seqnums: UID %d=seq1, UID %d=seq2, UID %d=seq3, UID %d=seq4, UID %d=seq5",
		uids[0], uids[1], uids[2], uids[3], uids[4])

	// Record the original sequence number for UID 3 (message 3)
	originalSeqForUID3 := uint32(3)

	// Step 3: Modify message 3 (change flags) - this should be in Modified response
	t.Logf("=== Step 3: Marking message 3 (UID %d) as \\Seen ===", uids[2])
	storeCmd := c.Store(imap.SeqSetNum(3), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		t.Fatalf("STORE failed: %v", err)
	}
	t.Log("  Message 3 flag changed (creates modseq > clientLastModSeq)")

	// Step 4: Expunge message 1 - this changes sequence numbers for all remaining messages
	t.Logf("=== Step 4: Expunging message 1 (UID %d) ===", uids[0])
	storeCmd = c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
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
	t.Logf("  Message 1 expunged - sequence numbers shifted down!")
	t.Logf("  NEW seqnums: UID %d=seq1, UID %d=seq2, UID %d=seq3, UID %d=seq4",
		uids[1], uids[2], uids[3], uids[4])
	t.Logf("  ⚠️  UID %d moved from seq3 → seq2", uids[2])

	// Step 5: Client performs QRESYNC with their last known modseq
	t.Logf("=== Step 5: Client QRESYNC with modseq=%d (before flag change) ===", clientLastModSeq)
	qresyncMbox, err := c.Select("INBOX", &imap.SelectOptions{
		QResync: &imap.QResyncData{
			UIDValidity: initialUIDValidity,
			ModSeq:      clientLastModSeq,
		},
	}).Wait()
	if err != nil {
		t.Fatalf("QRESYNC SELECT failed: %v", err)
	}

	t.Logf("QRESYNC response:")
	t.Logf("  NumMessages=%d, HighestModSeq=%d", qresyncMbox.NumMessages, qresyncMbox.HighestModSeq)
	t.Logf("  Vanished=%v", qresyncMbox.Vanished)
	t.Logf("  Modified messages=%d", len(qresyncMbox.Modified))

	// Step 6: Analyze the bug
	t.Log("=== Step 6: Analyzing sequence number staleness ===")

	// Check VANISHED includes UID 1
	foundUID1Vanished := false
	for _, uidRange := range qresyncMbox.Vanished {
		if uids[0] >= uidRange.Start && uids[0] <= uidRange.Stop {
			foundUID1Vanished = true
			break
		}
	}
	if !foundUID1Vanished {
		t.Errorf("❌ VANISHED missing UID %d (message 1)", uids[0])
	} else {
		t.Logf("✅ VANISHED includes UID %d", uids[0])
	}

	// Check Modified includes UID 3 with CURRENT sequence number
	foundUID3Modified := false
	var uid3SeqInModified uint32
	for _, mod := range qresyncMbox.Modified {
		if mod.UID == uids[2] {
			foundUID3Modified = true
			uid3SeqInModified = mod.SeqNum
			t.Logf("Modified: UID %d reported at SeqNum=%d, ModSeq=%d, Flags=%v",
				mod.UID, mod.SeqNum, mod.ModSeq, mod.Flags)
			break
		}
	}

	if !foundUID3Modified {
		t.Fatalf("❌ Modified missing UID %d (message 3 with flag change)", uids[2])
	}

	// VALIDATION: Server correctly reports CURRENT seqnum (not historical)
	t.Log("\n=== VALIDATION: Sequence Numbers Reflect Current State ===")
	t.Logf("Client's historical state (at modseq %d):", clientLastModSeq)
	t.Logf("  UID %d was at SeqNum=%d", uids[2], originalSeqForUID3)
	t.Logf("Server's response (CURRENT state after expunge):")
	t.Logf("  UID %d reported at SeqNum=%d", uids[2], uid3SeqInModified)

	if uid3SeqInModified != originalSeqForUID3 {
		t.Logf("\n✅ CORRECT: Sequence numbers reflect CURRENT state (not historical)")
		t.Logf("   Historical SeqNum=%d (client's last sync state)", originalSeqForUID3)
		t.Logf("   Current SeqNum=%d (after VANISHED UID 1 processed)", uid3SeqInModified)
		t.Logf("\n   RFC 7162 §3.2.5 Protocol Flow:")
		t.Logf("   1. Client receives VANISHED: UID 1")
		t.Logf("   2. Client processes VANISHED → removes UID 1 → shifts seqnums down")
		t.Logf("   3. Client receives Modified: UID %d at seqnum %d", uids[2], uid3SeqInModified)
		t.Logf("   4. Client's cache now matches server state → NO stuttering")
		t.Logf("\n   This is the CORRECT behavior - sequence numbers are current,")
		t.Logf("   and VANISHED response ensures client cache stays synchronized.")
	} else {
		t.Errorf("❌ UNEXPECTED: Sequence numbers match historical state")
		t.Errorf("   This would indicate sequence numbers are not being computed correctly")
	}

	// Additional check: Verify current state by fetching
	t.Log("\n=== Verification: Fetch current message at seqnum 2 ===")
	fetchCmd := c.Fetch(imap.SeqSetNum(2), &imap.FetchOptions{
		UID:   true,
		Flags: true,
	})
	fetchMsgs, err := fetchCmd.Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}
	if len(fetchMsgs) == 1 {
		t.Logf("Current message at seqnum 2: UID=%d, Flags=%v",
			fetchMsgs[0].UID, fetchMsgs[0].Flags)
		if fetchMsgs[0].UID == uids[2] {
			t.Logf("✅ Confirms UID %d is NOW at seqnum 2 (after expunge)", uids[2])
		}
	}

	t.Log("\n=== Test completed - QRESYNC behavior validated as correct ===")
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
