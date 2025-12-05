//go:build integration

package imap_test

import (
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_FlagsAnnouncement verifies that FETCH responses only include flags
// that were announced during SELECT. RFC 3501 Section 7.2.6 states:
// "Any flags that are in a message but not in the FLAGS response MUST NOT be returned in a FETCH FLAGS response"
func TestIMAP_FlagsAnnouncement(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Setup test account and server
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

	// Client 1: Create a mailbox and append a message with a custom flag
	if err := c.Create("TestMailbox", nil).Wait(); err != nil {
		t.Fatalf("Failed to create mailbox: %v", err)
	}

	testMessage := "From: test@example.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\nBody\r\n"

	appendCmd := c.Append("TestMailbox", int64(len(testMessage)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen, "$CustomFlag1"},
	})
	if _, err := appendCmd.Write([]byte(testMessage)); err != nil {
		t.Fatalf("Failed to write message: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("Failed to close append writer: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("Failed to append message: %v", err)
	}

	// Client 1: SELECT mailbox to see what flags are announced
	selectData, err := c.Select("TestMailbox", nil).Wait()
	if err != nil {
		t.Fatalf("Failed to SELECT mailbox: %v", err)
	}

	// Record which flags were announced
	announcedFlags := make(map[imap.Flag]struct{})
	for _, flag := range selectData.Flags {
		announcedFlags[flag] = struct{}{}
		t.Logf("Announced flag: %s", flag)
	}

	// Verify $CustomFlag1 was announced
	if _, ok := announcedFlags["$CustomFlag1"]; !ok {
		t.Error("Expected $CustomFlag1 to be announced in FLAGS response")
	}

	// Client 2: Connect and add a DIFFERENT custom flag to the same message
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Client 2: Failed to dial IMAP server: %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Client 2: Login failed: %v", err)
	}

	if _, err := c2.Select("TestMailbox", nil).Wait(); err != nil {
		t.Fatalf("Client 2: Failed to SELECT mailbox: %v", err)
	}

	// Add a new custom flag that Client 1 hasn't seen yet
	storeData, err := c2.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{"$CustomFlag2"},
	}, nil).Collect()
	if err != nil {
		t.Fatalf("Client 2: Failed to add $CustomFlag2: %v", err)
	}
	t.Logf("Client 2: Added $CustomFlag2, store result: %+v", storeData)

	// Client 1: FETCH flags WITHOUT re-selecting (no new FLAGS announcement)
	// According to RFC 3501, $CustomFlag2 should NOT appear in the FETCH response
	// because it wasn't in the original FLAGS response from SELECT
	fetchResults, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		Flags: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH command failed: %v", err)
	}

	if len(fetchResults) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(fetchResults))
	}

	fetchedFlags := fetchResults[0].Flags
	t.Logf("FETCH returned flags: %v", fetchedFlags)

	// Verify that $CustomFlag2 is NOT in the FETCH response
	for _, flag := range fetchedFlags {
		if flag == "$CustomFlag2" {
			t.Error("RFC 3501 violation: FETCH returned $CustomFlag2 which was not announced in FLAGS response during SELECT")
		}
		// Also verify all returned flags were announced
		if _, announced := announcedFlags[flag]; !announced {
			t.Errorf("RFC 3501 violation: FETCH returned flag %s which was not announced during SELECT", flag)
		}
	}

	// Client 1: Re-SELECT the mailbox - now $CustomFlag2 should be announced
	selectData2, err := c.Select("TestMailbox", nil).Wait()
	if err != nil {
		t.Fatalf("Failed to re-SELECT mailbox: %v", err)
	}

	// Check that $CustomFlag2 is now announced
	foundCustomFlag2 := false
	for _, flag := range selectData2.Flags {
		t.Logf("Re-SELECT announced flag: %s", flag)
		if flag == "$CustomFlag2" {
			foundCustomFlag2 = true
		}
	}

	if !foundCustomFlag2 {
		t.Error("Expected $CustomFlag2 to be announced after re-SELECT")
	}

	// Client 1: FETCH again - now $CustomFlag2 SHOULD appear
	fetchResults2, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		Flags: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH command failed: %v", err)
	}

	if len(fetchResults2) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(fetchResults2))
	}

	fetchedFlags2 := fetchResults2[0].Flags
	t.Logf("FETCH after re-SELECT returned flags: %v", fetchedFlags2)

	// Now $CustomFlag2 should be present
	foundInFetch := false
	for _, flag := range fetchedFlags2 {
		if flag == "$CustomFlag2" {
			foundInFetch = true
		}
	}

	if !foundInFetch {
		t.Error("Expected $CustomFlag2 to appear in FETCH response after re-SELECT announced it")
	}
}
