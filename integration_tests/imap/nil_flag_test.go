//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_NILNotAFlag tests that a message nobody gave the keyword NIL never
// shows one: no flags, an empty flag list or clearing all flags must not be
// serialized as a NIL keyword. (A client storing the keyword NIL gets it back;
// see TestIMAP_StoreNILKeyword.)
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

// TestIMAP_NILCustomFlagAttempt tests that "$NIL", a valid keyword atom, is
// stored on APPEND like any other keyword (#2013).
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
		t.Fatalf("APPEND with keyword $NIL failed: %v", err)
	}

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

	if !hasNILFlag {
		t.Errorf("keyword $NIL was dropped on APPEND: %v", flags)
	}
	if !hasValidFlag {
		t.Errorf("keyword $Valid was dropped on APPEND: %v", flags)
	}
}
