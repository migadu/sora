//go:build integration

package imap_test

import (
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_FlagOperations tests comprehensive flag operations
func TestIMAP_FlagOperations(t *testing.T) {
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

	// Select INBOX
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Add a test message
	testMessage := "From: flags@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Flag Operations Test\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This is a test message for flag operations.\r\n"

	appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	_, err = appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// Test 1: Store flags (add)
	storeCmd := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen, imap.FlagFlagged},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE flags add failed: %v", err)
	}

	// Verify flags were added
	fetchResults, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH after flag add failed: %v", err)
	}
	if len(fetchResults) == 0 {
		t.Fatal("FETCH returned no results")
	}

	flags := fetchResults[0].Flags
	if !containsFlag(flags, imap.FlagSeen) {
		t.Error("\\Seen flag not found after adding")
	}
	if !containsFlag(flags, imap.FlagFlagged) {
		t.Error("\\Flagged flag not found after adding")
	}
	t.Logf("Flags after adding: %v", flags)

	// Test 2: Store flags (remove)
	storeCmd = c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsDel,
		Flags: []imap.Flag{imap.FlagFlagged},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE flags remove failed: %v", err)
	}

	// Verify flag was removed
	fetchResults, err = c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH after flag remove failed: %v", err)
	}
	if len(fetchResults) == 0 {
		t.Fatal("FETCH returned no results")
	}

	flags = fetchResults[0].Flags
	if !containsFlag(flags, imap.FlagSeen) {
		t.Error("\\Seen flag should still be present")
	}
	if containsFlag(flags, imap.FlagFlagged) {
		t.Error("\\Flagged flag should be removed")
	}
	t.Logf("Flags after removing \\Flagged: %v", flags)

	// Test 3: Store flags (replace)
	storeCmd = c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsSet,
		Flags: []imap.Flag{imap.FlagAnswered, imap.FlagDraft},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE flags replace failed: %v", err)
	}

	// Verify flags were replaced
	fetchResults, err = c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH after flag replace failed: %v", err)
	}
	if len(fetchResults) == 0 {
		t.Fatal("FETCH returned no results")
	}

	flags = fetchResults[0].Flags
	if containsFlag(flags, imap.FlagSeen) {
		t.Error("\\Seen flag should be removed after replace")
	}
	if !containsFlag(flags, imap.FlagAnswered) {
		t.Error("\\Answered flag not found after replace")
	}
	if !containsFlag(flags, imap.FlagDraft) {
		t.Error("\\Draft flag not found after replace")
	}
	t.Logf("Flags after replace: %v", flags)

	t.Log("Flag operations test completed successfully")
}
