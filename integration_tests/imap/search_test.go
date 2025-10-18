//go:build integration

package imap_test

import (
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SearchOperations tests comprehensive search operations
func TestIMAP_SearchOperations(t *testing.T) {
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

	// Add test messages with different characteristics
	messages := []struct {
		subject string
		from    string
		flags   []imap.Flag
		body    string
	}{
		{
			subject: "Search Test Alpha",
			from:    "alpha@example.com",
			flags:   []imap.Flag{imap.FlagSeen},
			body:    "This message contains the keyword alpha.",
		},
		{
			subject: "Search Test Beta",
			from:    "beta@example.com",
			flags:   []imap.Flag{imap.FlagFlagged},
			body:    "This message contains the keyword beta.",
		},
		{
			subject: "Search Test Gamma",
			from:    "gamma@example.com",
			flags:   []imap.Flag{imap.FlagSeen, imap.FlagAnswered},
			body:    "This message contains the keyword gamma.",
		},
	}

	for i, msg := range messages {
		testMessage := "From: " + msg.from + "\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: " + msg.subject + "\r\n" +
			"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
			"\r\n" +
			msg.body + "\r\n"

		appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
			Flags: msg.flags,
			Time:  time.Now(),
		})
		_, err = appendCmd.Write([]byte(testMessage))
		if err != nil {
			t.Fatalf("APPEND write message %d failed: %v", i+1, err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("APPEND close message %d failed: %v", i+1, err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND message %d failed: %v", i+1, err)
		}
	}

	// Test 1: Search by flag
	searchResults, err := c.Search(&imap.SearchCriteria{
		Flag: []imap.Flag{imap.FlagSeen},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH by \\Seen flag failed: %v", err)
	}

	seenMessages := searchResults.AllSeqNums()
	if len(seenMessages) != 2 {
		t.Errorf("Expected 2 messages with \\Seen flag, got %d", len(seenMessages))
	}
	t.Logf("SEARCH by \\Seen flag found %d messages: %v", len(seenMessages), seenMessages)

	// Test 2: Search by subject
	searchResults, err = c.Search(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{
			{Key: "Subject", Value: "Alpha"},
		},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH by subject failed: %v", err)
	}

	subjectMessages := searchResults.AllSeqNums()
	if len(subjectMessages) != 1 {
		t.Errorf("Expected 1 message with 'Alpha' in subject, got %d", len(subjectMessages))
	}
	t.Logf("SEARCH by subject 'Alpha' found %d messages: %v", len(subjectMessages), subjectMessages)

	// Test 3: Search by from
	searchResults, err = c.Search(&imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{
			{Key: "From", Value: "beta@example.com"},
		},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH by from failed: %v", err)
	}

	fromMessages := searchResults.AllSeqNums()
	if len(fromMessages) != 1 {
		t.Errorf("Expected 1 message from 'beta@example.com', got %d", len(fromMessages))
	}
	t.Logf("SEARCH by from 'beta@example.com' found %d messages: %v", len(fromMessages), fromMessages)

	// Test 4: Search ALL
	searchResults, err = c.Search(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH ALL failed: %v", err)
	}

	allMessages := searchResults.AllSeqNums()
	if len(allMessages) != 3 {
		t.Errorf("Expected 3 messages in ALL search, got %d", len(allMessages))
	}
	t.Logf("SEARCH ALL found %d messages: %v", len(allMessages), allMessages)

	// Test 5: Search NOT
	searchResults, err = c.Search(&imap.SearchCriteria{
		Not: []imap.SearchCriteria{
			{Flag: []imap.Flag{imap.FlagSeen}},
		},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("SEARCH NOT \\Seen failed: %v", err)
	}

	notSeenMessages := searchResults.AllSeqNums()
	if len(notSeenMessages) != 1 {
		t.Errorf("Expected 1 message without \\Seen flag, got %d", len(notSeenMessages))
	}
	t.Logf("SEARCH NOT \\Seen found %d messages: %v", len(notSeenMessages), notSeenMessages)

	t.Log("Search operations test completed successfully")
}

// TestIMAP_ESearchEmptyResult tests ESEARCH with empty results
//
// This test verifies that empty ESEARCH responses are formatted correctly:
// "* ESEARCH (TAG "X") UID" without the "ALL" keyword when there are no results.
//
// This was previously broken in upstream go-imap but is now fixed in our fork.
func TestIMAP_ESearchEmptyResult(t *testing.T) {
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

	// Add a single test message so we have something in the mailbox
	testMessage := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Test Message\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"Test body\r\n"

	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen},
		Time:  time.Now(),
	})
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

	// Test 1: UID SEARCH with RETURN (ALL) for non-existent UID
	// This should return empty results: "* ESEARCH (TAG "X") UID" without "ALL"
	searchResults, err := c.UIDSearch(&imap.SearchCriteria{
		UID: []imap.UIDSet{imap.UIDSetNum(99999)}, // Non-existent UID
	}, &imap.SearchOptions{
		ReturnAll: true,
	}).Wait()
	if err != nil {
		t.Fatalf("UID SEARCH RETURN (ALL) failed: %v", err)
	}

	uids := searchResults.AllUIDs()
	if len(uids) != 0 {
		t.Errorf("Expected 0 UIDs in empty search result, got %d: %v", len(uids), uids)
	}
	t.Logf("UID SEARCH RETURN (ALL) for non-existent UID correctly returned empty result")

	// Test 2: UID SEARCH with RETURN (MIN MAX ALL) for non-existent UID
	searchResults, err = c.UIDSearch(&imap.SearchCriteria{
		UID: []imap.UIDSet{imap.UIDSetNum(99999)},
	}, &imap.SearchOptions{
		ReturnMin: true,
		ReturnMax: true,
		ReturnAll: true,
	}).Wait()
	if err != nil {
		t.Fatalf("UID SEARCH RETURN (MIN MAX ALL) failed: %v", err)
	}

	uids = searchResults.AllUIDs()
	if len(uids) != 0 {
		t.Errorf("Expected 0 UIDs in empty search result, got %d: %v", len(uids), uids)
	}
	if searchResults.Min != 0 {
		t.Errorf("Expected Min=0 for empty result, got %d", searchResults.Min)
	}
	if searchResults.Max != 0 {
		t.Errorf("Expected Max=0 for empty result, got %d", searchResults.Max)
	}
	t.Logf("UID SEARCH RETURN (MIN MAX ALL) for non-existent UID correctly returned empty result")

	// Test 3: Regular SEARCH (non-UID) with RETURN (ALL) for non-existent sequence
	searchResults, err = c.Search(&imap.SearchCriteria{
		SeqNum: []imap.SeqSet{imap.SeqSetNum(99999)}, // Non-existent sequence number
	}, &imap.SearchOptions{
		ReturnAll: true,
	}).Wait()
	if err != nil {
		t.Fatalf("SEARCH RETURN (ALL) failed: %v", err)
	}

	seqNums := searchResults.AllSeqNums()
	if len(seqNums) != 0 {
		t.Errorf("Expected 0 sequence numbers in empty search result, got %d: %v", len(seqNums), seqNums)
	}
	t.Logf("SEARCH RETURN (ALL) for non-existent sequence correctly returned empty result")

	// Test 4: Standard SEARCH (no RETURN clause) - should work fine
	// Standard SEARCH doesn't use ESEARCH format so no encoder bug
	searchResults, err = c.UIDSearch(&imap.SearchCriteria{
		UID: []imap.UIDSet{imap.UIDSetNum(99999)},
	}, nil).Wait()
	if err != nil {
		t.Fatalf("UID SEARCH (standard) failed: %v", err)
	}

	uids = searchResults.AllUIDs()
	if len(uids) != 0 {
		t.Errorf("Expected 0 UIDs in empty search result, got %d: %v", len(uids), uids)
	}
	t.Logf("UID SEARCH (standard) for non-existent UID correctly returned empty result")

	// Test 5: Search by non-existent flag with RETURN (ALL)
	searchResults, err = c.UIDSearch(&imap.SearchCriteria{
		Flag: []imap.Flag{imap.FlagFlagged}, // Our message doesn't have this flag
	}, &imap.SearchOptions{
		ReturnAll: true,
	}).Wait()
	if err != nil {
		t.Fatalf("UID SEARCH by non-existent flag failed: %v", err)
	}

	uids = searchResults.AllUIDs()
	if len(uids) != 0 {
		t.Errorf("Expected 0 UIDs when searching for non-existent flag, got %d: %v", len(uids), uids)
	}
	t.Logf("UID SEARCH by non-existent flag correctly returned empty result")

	t.Log("ESEARCH empty result test completed successfully")
}
