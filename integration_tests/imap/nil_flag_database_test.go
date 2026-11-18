//go:build integration

package imap_test

import (
	"context"
	"slices"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_NILFlagAlreadyInDatabase tests that a NIL keyword already stored in
// the database is returned on read. NIL is an atom, hence a valid keyword
// (flag-keyword = atom, RFC 3501 §9 / RFC 9051 §9); earlier releases dropped it
// on read, which lost a client's keyword (#2013).
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

	// Inject a NIL keyword directly into the database, as an earlier release
	// that accepted it would have stored it
	ctx := context.Background()

	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("Failed to get account ID: %v", err)
	}

	mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	if err != nil {
		t.Fatalf("Failed to get INBOX: %v", err)
	}

	t.Log("Injecting NIL flag directly into database...")
	_, err = server.ResilientDB.ExecWithRetry(ctx, `
		UPDATE message_state
		SET custom_flags = jsonb_build_array('$Valid', 'NIL', '$Another')
		WHERE message_id = (SELECT id FROM messages WHERE uid = $1 AND mailbox_id = $2)
	`, uid, mailbox.ID)
	if err != nil {
		t.Fatalf("Failed to inject NIL flag: %v", err)
	}

	t.Log("NIL flag injected. Re-selecting to update announced flags...")

	// Re-select INBOX to update the announcedFlags with the new flags from database
	_, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Failed to re-select INBOX after injection: %v", err)
	}

	t.Log("Now fetching message to verify NIL is returned...")

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

	if !slices.Contains(fetchedFlags, imap.Flag("NIL")) {
		t.Errorf("❌ stored keyword NIL was dropped on FETCH: %v", fetchedFlags)
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

	// The SELECT FLAGS response lists the keyword in use too
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Failed to re-select INBOX: %v", err)
	}

	t.Logf("SELECT FLAGS: %v", selectData.Flags)

	if !slices.Contains(selectData.Flags, imap.Flag("NIL")) {
		t.Errorf("❌ keyword NIL in use is missing from SELECT FLAGS: %v", selectData.Flags)
	}
}
