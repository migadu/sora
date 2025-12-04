//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_NILNotAFlag tests that NIL never appears as a flag
// This is a regression test for imaptest error:
// "Keyword used without being in FLAGS: NIL: * 1 FETCH (FLAGS (\Recent NIL) UID 1 MODSEQ (116))"
//
// NIL is not a valid flag and should never appear in FLAGS responses.
// This could happen if:
// 1. Malformed input is stored (literal string "NIL" as a flag)
// 2. NULL values in database are incorrectly serialized as "NIL"
// 3. Empty/null flag handling bug
func TestIMAP_NILNotAFlag(t *testing.T) {
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

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Test 1: Append message with no flags
	t.Log("=== Test 1: Message with no flags ===")
	testMessage := "From: test@example.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\nBody\r\n"

	appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appendData1, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// Fetch flags - should not include NIL
	fetchResults, err := c.Fetch(imap.UIDSetNum(appendData1.UID), &imap.FetchOptions{
		UID:   true,
		Flags: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}

	if len(fetchResults) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(fetchResults))
	}

	flags := fetchResults[0].Flags
	t.Logf("Flags: %v", flags)

	// Check for NIL
	for _, flag := range flags {
		if strings.ToUpper(string(flag)) == "NIL" {
			t.Errorf("❌ NIL found in FLAGS response: %v", flags)
		}
	}

	// Test 2: Append message with empty flags array
	t.Log("=== Test 2: Message with empty flags array ===")
	appendCmd = c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Flags: []imap.Flag{},
	})
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appendData2, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	fetchResults, err = c.Fetch(imap.UIDSetNum(appendData2.UID), &imap.FetchOptions{
		UID:   true,
		Flags: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}

	if len(fetchResults) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(fetchResults))
	}

	flags = fetchResults[0].Flags
	t.Logf("Flags: %v", flags)

	for _, flag := range flags {
		if strings.ToUpper(string(flag)) == "NIL" {
			t.Errorf("❌ NIL found in FLAGS response: %v", flags)
		}
	}

	// Test 3: Try to set flags with variations of nil/empty
	// (The client library should reject these, but let's verify server behavior)
	t.Log("=== Test 3: STORE with valid flags then FETCH ===")

	storeCmd := c.Store(imap.UIDSetNum(appendData2.UID), &imap.StoreFlags{
		Op:    imap.StoreFlagsSet,
		Flags: []imap.Flag{imap.FlagSeen, "$Test"},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	fetchResults, err = c.Fetch(imap.UIDSetNum(appendData2.UID), &imap.FetchOptions{
		UID:   true,
		Flags: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}

	if len(fetchResults) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(fetchResults))
	}

	flags = fetchResults[0].Flags
	t.Logf("Flags after STORE: %v", flags)

	for _, flag := range flags {
		flagStr := string(flag)
		flagUpper := strings.ToUpper(flagStr)

		if flagUpper == "NIL" {
			t.Errorf("❌ NIL found in FLAGS response after STORE: %v", flags)
		}

		// Also check for empty flags
		if flagStr == "" {
			t.Errorf("❌ Empty string found in FLAGS response: %v", flags)
		}

		// Check for null-like values
		if flagUpper == "NULL" {
			t.Errorf("❌ NULL found in FLAGS response: %v", flags)
		}
	}

	// Test 4: STORE removing all flags
	t.Log("=== Test 4: STORE removing all flags ===")
	storeCmd = c.Store(imap.UIDSetNum(appendData2.UID), &imap.StoreFlags{
		Op:    imap.StoreFlagsSet,
		Flags: []imap.Flag{},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE failed: %v", err)
	}

	fetchResults, err = c.Fetch(imap.UIDSetNum(appendData2.UID), &imap.FetchOptions{
		UID:   true,
		Flags: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}

	if len(fetchResults) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(fetchResults))
	}

	flags = fetchResults[0].Flags
	t.Logf("Flags after clearing: %v", flags)

	for _, flag := range flags {
		if strings.ToUpper(string(flag)) == "NIL" {
			t.Errorf("❌ NIL found in FLAGS response after clearing flags: %v", flags)
		}
	}

	// Test 5: Check FLAGS response doesn't include NIL
	t.Log("=== Test 5: SELECT FLAGS response ===")
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}

	t.Logf("Mailbox FLAGS: %v", selectData.Flags)

	for _, flag := range selectData.Flags {
		flagUpper := strings.ToUpper(string(flag))
		if flagUpper == "NIL" || flagUpper == "NULL" || string(flag) == "" {
			t.Errorf("❌ Invalid flag %q found in FLAGS response: %v", flag, selectData.Flags)
		}
	}

	t.Log("✅ All NIL flag tests passed - NIL never appears as a flag")
}

// TestIMAP_NILCustomFlagAttempt tests that attempting to use "NIL" as a custom flag
// is rejected or sanitized
func TestIMAP_NILCustomFlagAttempt(t *testing.T) {
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

	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	testMessage := "From: test@example.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\nBody\r\n"

	// Try to append with "NIL" as a custom flag
	// The go-imap client might reject this, but let's see what happens
	t.Log("=== Attempting to use NIL-like strings as flags ===")

	// Test with "$NIL" which is technically a valid custom flag format
	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Flags: []imap.Flag{"$NIL", "$Valid"},
	})
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Logf("APPEND with $NIL flag rejected (expected): %v", err)
		// This is acceptable - server can reject NIL-like flags
		return
	}

	// If APPEND succeeded, verify the flags
	fetchResults, err := c.Fetch(imap.UIDSetNum(appendData.UID), &imap.FetchOptions{
		UID:   true,
		Flags: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}

	if len(fetchResults) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(fetchResults))
	}

	flags := fetchResults[0].Flags
	t.Logf("Flags returned: %v", flags)

	// Check what was actually stored
	hasValidFlag := false
	hasNILFlag := false

	for _, flag := range flags {
		if flag == "$Valid" {
			hasValidFlag = true
		}
		if strings.ToUpper(string(flag)) == "$NIL" || strings.ToUpper(string(flag)) == "NIL" {
			hasNILFlag = true
		}
	}

	if hasNILFlag {
		t.Errorf("⚠️  Server accepted and stored $NIL flag (should ideally reject or sanitize)")
		t.Logf("   This could lead to the imaptest error: 'Keyword used without being in FLAGS: NIL'")
	}

	if hasValidFlag {
		t.Logf("✅ Valid flag $Valid was stored correctly")
	}
}
