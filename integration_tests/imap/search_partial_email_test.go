//go:build integration

package imap_test

import (
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SearchPartialEmail tests partial email address search
func TestIMAP_SearchPartialEmail(t *testing.T) {
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

	// Append test messages with different email addresses and display names
	messages := []struct {
		from    string
		to      string
		cc      string
		subject string
	}{
		{
			from:    "Peter Smith <peter@whatever.com>",
			to:      "alice@example.com",
			cc:      "bob@company.org",
			subject: "Test 1",
		},
		{
			from:    "john@whatever.com",
			to:      "Peter Jones <peter@example.org>",
			cc:      "alice@company.org",
			subject: "Test 2",
		},
		{
			from:    "alice@example.com",
			to:      "peter@whatever.com",
			cc:      "john@whatever.com",
			subject: "Test 3",
		},
		{
			from:    "Robert Johnson <bob@someother.net>",
			to:      "test@example.com",
			cc:      "admin@whatever.com",
			subject: "Test 4",
		},
	}

	for i, msg := range messages {
		testMessage := "From: " + msg.from + "\r\n" +
			"To: " + msg.to + "\r\n" +
			"Cc: " + msg.cc + "\r\n" +
			"Subject: " + msg.subject + "\r\n" +
			"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
			"\r\n" +
			"Test message body\r\n"

		appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
			Time: time.Now(),
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

	// Test 1: Search for "peter" in FROM field (should find messages 1 and 2)
	t.Run("Partial FROM local part", func(t *testing.T) {
		searchResults, err := c.Search(&imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{
				{Key: "From", Value: "peter"},
			},
		}, nil).Wait()
		if err != nil {
			t.Fatalf("SEARCH by FROM peter failed: %v", err)
		}

		fromMessages := searchResults.AllSeqNums()
		if len(fromMessages) != 1 {
			t.Errorf("Expected 1 message from 'peter', got %d: %v", len(fromMessages), fromMessages)
		}
		t.Logf("SEARCH FROM peter found %d messages: %v", len(fromMessages), fromMessages)
	})

	// Test 2: Search for "whatever.com" in FROM field (should find messages 1 and 2)
	t.Run("Partial FROM domain", func(t *testing.T) {
		searchResults, err := c.Search(&imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{
				{Key: "From", Value: "whatever.com"},
			},
		}, nil).Wait()
		if err != nil {
			t.Fatalf("SEARCH by FROM whatever.com failed: %v", err)
		}

		fromMessages := searchResults.AllSeqNums()
		if len(fromMessages) != 2 {
			t.Errorf("Expected 2 messages from 'whatever.com', got %d: %v", len(fromMessages), fromMessages)
		}
		t.Logf("SEARCH FROM whatever.com found %d messages: %v", len(fromMessages), fromMessages)
	})

	// Test 3: Search for "peter" in TO field (should find messages 2 and 3)
	t.Run("Partial TO local part", func(t *testing.T) {
		searchResults, err := c.Search(&imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{
				{Key: "To", Value: "peter"},
			},
		}, nil).Wait()
		if err != nil {
			t.Fatalf("SEARCH by TO peter failed: %v", err)
		}

		toMessages := searchResults.AllSeqNums()
		if len(toMessages) != 2 {
			t.Errorf("Expected 2 messages to 'peter', got %d: %v", len(toMessages), toMessages)
		}
		t.Logf("SEARCH TO peter found %d messages: %v", len(toMessages), toMessages)
	})

	// Test 4: Search for "whatever.com" in CC field (should find messages 3 and 4)
	t.Run("Partial CC domain", func(t *testing.T) {
		searchResults, err := c.Search(&imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{
				{Key: "Cc", Value: "whatever.com"},
			},
		}, nil).Wait()
		if err != nil {
			t.Fatalf("SEARCH by CC whatever.com failed: %v", err)
		}

		ccMessages := searchResults.AllSeqNums()
		if len(ccMessages) != 2 {
			t.Errorf("Expected 2 messages cc'ing 'whatever.com', got %d: %v", len(ccMessages), ccMessages)
		}
		t.Logf("SEARCH CC whatever.com found %d messages: %v", len(ccMessages), ccMessages)
	})

	// Test 5: Full email address still works (should find message 1)
	t.Run("Full email address FROM", func(t *testing.T) {
		searchResults, err := c.Search(&imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{
				{Key: "From", Value: "peter@whatever.com"},
			},
		}, nil).Wait()
		if err != nil {
			t.Fatalf("SEARCH by FROM peter@whatever.com failed: %v", err)
		}

		fromMessages := searchResults.AllSeqNums()
		if len(fromMessages) != 1 {
			t.Errorf("Expected 1 message from 'peter@whatever.com', got %d: %v", len(fromMessages), fromMessages)
		}
		t.Logf("SEARCH FROM peter@whatever.com found %d messages: %v", len(fromMessages), fromMessages)
	})

	// Test 6: Partial match in middle of email (should find alice@company.org)
	t.Run("Partial CC middle match", func(t *testing.T) {
		searchResults, err := c.Search(&imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{
				{Key: "Cc", Value: "company"},
			},
		}, nil).Wait()
		if err != nil {
			t.Fatalf("SEARCH by CC company failed: %v", err)
		}

		ccMessages := searchResults.AllSeqNums()
		if len(ccMessages) != 2 {
			t.Errorf("Expected 2 messages cc'ing 'company', got %d: %v", len(ccMessages), ccMessages)
		}
		t.Logf("SEARCH CC company found %d messages: %v", len(ccMessages), ccMessages)
	})

	// Test 7: Search by FROM display name (should find message 1 - "Peter Smith")
	t.Run("Search FROM by display name", func(t *testing.T) {
		searchResults, err := c.Search(&imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{
				{Key: "From", Value: "Smith"},
			},
		}, nil).Wait()
		if err != nil {
			t.Fatalf("SEARCH by FROM Smith failed: %v", err)
		}

		fromMessages := searchResults.AllSeqNums()
		if len(fromMessages) != 1 {
			t.Errorf("Expected 1 message from 'Smith', got %d: %v", len(fromMessages), fromMessages)
		}
		t.Logf("SEARCH FROM Smith found %d messages: %v", len(fromMessages), fromMessages)
	})

	// Test 8: Search by TO display name (should find message 2 - "Peter Jones")
	t.Run("Search TO by display name", func(t *testing.T) {
		searchResults, err := c.Search(&imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{
				{Key: "To", Value: "Jones"},
			},
		}, nil).Wait()
		if err != nil {
			t.Fatalf("SEARCH by TO Jones failed: %v", err)
		}

		toMessages := searchResults.AllSeqNums()
		if len(toMessages) != 1 {
			t.Errorf("Expected 1 message to 'Jones', got %d: %v", len(toMessages), toMessages)
		}
		t.Logf("SEARCH TO Jones found %d messages: %v", len(toMessages), toMessages)
	})

	// Test 9: Search by FROM display name partial (should find message 4 - "Robert Johnson")
	t.Run("Search FROM by partial display name", func(t *testing.T) {
		searchResults, err := c.Search(&imap.SearchCriteria{
			Header: []imap.SearchCriteriaHeaderField{
				{Key: "From", Value: "robert"},
			},
		}, nil).Wait()
		if err != nil {
			t.Fatalf("SEARCH by FROM robert failed: %v", err)
		}

		fromMessages := searchResults.AllSeqNums()
		if len(fromMessages) != 1 {
			t.Errorf("Expected 1 message from 'robert', got %d: %v", len(fromMessages), fromMessages)
		}
		t.Logf("SEARCH FROM robert found %d messages: %v", len(fromMessages), fromMessages)
	})
}
