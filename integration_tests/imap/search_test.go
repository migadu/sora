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
