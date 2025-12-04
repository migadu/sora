//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_KeywordFlagsAnnounced tests that custom keyword flags are properly announced
// in the FLAGS response before being used.
//
// This is a regression test for the imaptest issue:
// "Keyword FLAGS Not Announced - Uses keywords without announcing in FLAGS"
//
// Expected behavior per RFC 3501:
// - FLAGS response should list all flags defined for the mailbox
// - This includes custom keywords (like $Label1, $Important, etc.)
// - Keywords must be announced before they can be used/seen
func TestIMAP_KeywordFlagsAnnounced(t *testing.T) {
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

	// Append a message with custom keywords
	testMessage := "From: test@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Test Keywords\r\n" +
		"\r\n" +
		"Test body\r\n"

	customKeywords := []imap.Flag{"$Label1", "$Important", "$Work"}
	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Flags: append([]imap.Flag{imap.FlagSeen}, customKeywords...),
	})
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}
	t.Logf("Appended message with UID %d and custom keywords: %v", appendData.UID, customKeywords)

	// Select INBOX and check FLAGS response
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	t.Logf("FLAGS response: %v", selectData.Flags)
	t.Logf("PERMANENTFLAGS response: %v", selectData.PermanentFlags)

	// Verify that custom keywords are announced in FLAGS
	flagsMap := make(map[imap.Flag]bool)
	for _, flag := range selectData.Flags {
		flagsMap[flag] = true
	}

	for _, keyword := range customKeywords {
		if !flagsMap[keyword] {
			t.Errorf("Custom keyword %q was used but not announced in FLAGS response", keyword)
			t.Errorf("FLAGS response was: %v", selectData.Flags)
		} else {
			t.Logf("✓ Keyword %q correctly announced in FLAGS", keyword)
		}
	}

	// Verify PERMANENTFLAGS includes \*
	hasWildcard := false
	for _, flag := range selectData.PermanentFlags {
		if flag == imap.FlagWildcard {
			hasWildcard = true
			break
		}
	}
	if !hasWildcard {
		t.Error("PERMANENTFLAGS should include \\* to indicate custom keywords are supported")
	} else {
		t.Log("✓ PERMANENTFLAGS includes \\* for custom keyword support")
	}

	// Fetch the message and verify keywords are returned
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

	returnedFlags := fetchResults[0].Flags
	t.Logf("Message flags: %v", returnedFlags)

	// Verify all custom keywords are present in the returned flags
	returnedFlagsMap := make(map[imap.Flag]bool)
	for _, flag := range returnedFlags {
		returnedFlagsMap[flag] = true
	}

	for _, keyword := range customKeywords {
		if !returnedFlagsMap[keyword] {
			t.Errorf("Custom keyword %q was not returned in FETCH FLAGS", keyword)
		} else {
			t.Logf("✓ Keyword %q correctly returned in message flags", keyword)
		}
	}
}

// TestIMAP_KeywordFlagsMultipleMessages tests that FLAGS response includes
// keywords from multiple messages
func TestIMAP_KeywordFlagsMultipleMessages(t *testing.T) {
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

	testMessage := "From: test@example.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\nBody\r\n"

	// Append multiple messages with different keywords
	keywordSets := [][]imap.Flag{
		{"$Label1", "$Important"},
		{"$Label2", "$Work"},
		{"$Label3", "$Personal"},
	}

	for i, keywords := range keywordSets {
		appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
			Flags: keywords,
		})
		_, err = appendCmd.Write([]byte(testMessage))
		if err != nil {
			t.Fatalf("APPEND write failed for message %d: %v", i+1, err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("APPEND close failed for message %d: %v", i+1, err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND failed for message %d: %v", i+1, err)
		}
		t.Logf("Appended message %d with keywords: %v", i+1, keywords)
	}

	// Select INBOX
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	t.Logf("FLAGS response: %v", selectData.Flags)

	// Verify ALL keywords from all messages are announced
	allKeywords := []imap.Flag{"$Label1", "$Important", "$Label2", "$Work", "$Label3", "$Personal"}
	flagsMap := make(map[imap.Flag]bool)
	for _, flag := range selectData.Flags {
		flagsMap[flag] = true
	}

	for _, keyword := range allKeywords {
		if !flagsMap[keyword] {
			t.Errorf("Keyword %q used in mailbox but not announced in FLAGS", keyword)
		} else {
			t.Logf("✓ Keyword %q correctly announced", keyword)
		}
	}
}

// TestIMAP_KeywordFlagsUpdated tests that FLAGS response is updated
// when new keywords are added via STORE
func TestIMAP_KeywordFlagsUpdated(t *testing.T) {
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
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	// Append a message with no keywords
	testMessage := "From: test@example.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\nBody\r\n"
	appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
	_, err = appendCmd.Write([]byte(testMessage))
	if err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	err = appendCmd.Close()
	if err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// Add a new keyword via STORE
	newKeyword := imap.Flag("$NewLabel")
	storeCmd := c.Store(imap.UIDSetNum(appendData.UID), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{newKeyword},
	}, nil)
	storeResults, err := storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE failed: %v", err)
	}
	t.Logf("STORE results: %d messages updated", len(storeResults))

	// Re-SELECT to get updated FLAGS
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT INBOX (second time) failed: %v", err)
	}

	t.Logf("FLAGS after STORE: %v", selectData.Flags)

	// Verify the new keyword is now announced
	found := false
	for _, flag := range selectData.Flags {
		if flag == newKeyword {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Keyword %q added via STORE but not announced in FLAGS after re-SELECT", newKeyword)
		t.Errorf("FLAGS response was: %v", selectData.Flags)
	} else {
		t.Logf("✓ Keyword %q correctly announced after STORE", newKeyword)
	}
}

// TestIMAP_StandardKeywordsAnnounced tests that common standard keywords
// are pre-announced even if not yet used
func TestIMAP_StandardKeywordsAnnounced(t *testing.T) {
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

	// Select empty INBOX
	selectData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	t.Logf("FLAGS response (empty mailbox): %v", selectData.Flags)

	// These common keywords should be pre-announced even in empty mailbox
	expectedKeywords := []string{"$Forwarded", "$Important", "$Junk", "$NotJunk", "$Phishing"}

	flagsStr := strings.Join(func() []string {
		strs := make([]string, len(selectData.Flags))
		for i, f := range selectData.Flags {
			strs[i] = string(f)
		}
		return strs
	}(), " ")

	for _, keyword := range expectedKeywords {
		if strings.Contains(flagsStr, keyword) {
			t.Logf("✓ Standard keyword %q pre-announced", keyword)
		} else {
			t.Logf("⚠ Standard keyword %q not pre-announced (optional, but recommended)", keyword)
		}
	}

	// Verify system flags are announced
	systemFlags := []imap.Flag{
		imap.FlagSeen,
		imap.FlagAnswered,
		imap.FlagFlagged,
		imap.FlagDeleted,
		imap.FlagDraft,
	}

	flagsMap := make(map[imap.Flag]bool)
	for _, flag := range selectData.Flags {
		flagsMap[flag] = true
	}

	for _, flag := range systemFlags {
		if !flagsMap[flag] {
			t.Errorf("System flag %q not announced in FLAGS", flag)
		} else {
			t.Logf("✓ System flag %q announced", flag)
		}
	}
}
