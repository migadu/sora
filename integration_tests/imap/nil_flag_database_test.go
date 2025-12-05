//go:build integration

package imap_test

import (
	"context"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_NILFlagAlreadyInDatabase tests that NIL flags that already exist
// in the database (stored before validation was added) are properly filtered
// out when reading flags.
//
// This test simulates the scenario where NIL flags were stored in the database
// before validation was implemented, ensuring they are filtered out on read.
func TestIMAP_NILFlagAlreadyInDatabase(t *testing.T) {
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
	_, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Failed to select INBOX: %v", err)
	}

	t.Log("=== Simulating NIL flag stored in database before validation ===")

	// Append a message with valid flags first
	testMessage := "From: test@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Test NIL Flag\r\n" +
		"\r\n" +
		"Test body\r\n"

	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Flags: []imap.Flag{"$Valid"},
	})
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("Failed to append message: %v", err)
	}

	uid := appendData.UID

	// Now manually inject a NIL flag directly into the database to simulate
	// a flag that was stored before validation was added
	ctx := context.Background()

	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatalf("Failed to get INBOX: %v", err)
	}

	// Directly update the database to add NIL as a custom flag
	// This simulates what would happen if NIL was stored before validation
	t.Log("Injecting NIL flag directly into database...")
	_, err = server.ResilientDB.ExecWithRetry(ctx, `
		UPDATE messages
		SET custom_flags = jsonb_build_array('$Valid', 'NIL', '$Another')
		WHERE uid = $1 AND mailbox_id = $2
	`, uid, mailbox.ID)
	if err != nil {
		t.Fatalf("Failed to inject NIL flag: %v", err)
	}

	t.Log("NIL flag injected. Re-selecting to update announced flags...")

	// Re-select INBOX to update the announcedFlags with the new flags from database
	// This simulates a fresh session that sees the NIL flag in the database
	_, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Failed to re-select INBOX after injection: %v", err)
	}

	t.Log("Now fetching message to verify NIL is filtered out...")

	// Fetch the message flags - NIL should be filtered out
	uidSet := imap.UIDSet{}
	uidSet.AddNum(uid)

	fetchResults, err := c.Fetch(uidSet, &imap.FetchOptions{
		UID:   true,
		Flags: true,
	}).Collect()
	if err != nil {
		t.Fatalf("Failed to fetch: %v", err)
	}

	if len(fetchResults) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(fetchResults))
	}

	fetchedFlags := fetchResults[0].Flags

	t.Logf("Fetched flags: %v", fetchedFlags)

	// Verify NIL is NOT in the flags
	for _, flag := range fetchedFlags {
		flagStr := string(flag)
		if flagStr == "NIL" || flagStr == "$NIL" {
			t.Errorf("❌ NIL flag was NOT filtered out! Flags: %v", fetchedFlags)
		}
	}

	// Verify valid flags are still present
	hasValid := false
	hasAnother := false
	for _, flag := range fetchedFlags {
		if flag == "$Valid" {
			hasValid = true
		}
		if flag == "$Another" {
			hasAnother = true
		}
	}

	if !hasValid {
		t.Errorf("❌ Valid flag $Valid was incorrectly filtered out: %v", fetchedFlags)
	}
	if !hasAnother {
		t.Errorf("❌ Valid flag $Another was incorrectly filtered out: %v", fetchedFlags)
	}

	// Also check SELECT FLAGS response - NIL should not appear there either
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Failed to re-select INBOX: %v", err)
	}

	t.Logf("SELECT FLAGS: %v", selectData.Flags)

	for _, flag := range selectData.Flags {
		flagStr := string(flag)
		if flagStr == "NIL" || flagStr == "$NIL" {
			t.Errorf("❌ NIL flag appears in SELECT FLAGS response: %v", selectData.Flags)
		}
	}

	t.Log("✅ NIL flag successfully filtered from database - never exposed to client")
}
