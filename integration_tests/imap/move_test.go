//go:build integration

package imap_test

import (
	"strings"
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_MoveOperations tests MOVE operations (if supported)
func TestIMAP_MoveOperations(t *testing.T) {
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

	// Create destination mailbox
	destMailbox := "MoveTest"
	if err := c.Create(destMailbox, nil).Wait(); err != nil {
		t.Fatalf("CREATE destination mailbox failed: %v", err)
	}
	defer func() {
		c.Delete(destMailbox).Wait()
	}()

	// Select INBOX
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}

	// Add test message
	testMessage := "From: move@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Move Test Message\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"This is a test message for move operations.\r\n"

	appendCmd := c.Append("INBOX", int64(len(testMessage)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen, imap.FlagImportant},
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

	// Get initial message count in INBOX
	inboxData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	initialInboxCount := inboxData.NumMessages
	t.Logf("Initial INBOX message count: %d", initialInboxCount)

	// Attempt MOVE operation
	moveData, err := c.Move(imap.SeqSetNum(1), destMailbox).Wait()
	if err != nil {
		if strings.Contains(err.Error(), "MOVE") || strings.Contains(err.Error(), "not supported") {
			t.Skip("MOVE command not supported by server")
		}
		t.Fatalf("MOVE failed: %v", err)
	}
	t.Logf("MOVE successful - move data: %+v", moveData)

	// Verify message was removed from INBOX
	inboxData, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX after move failed: %v", err)
	}
	if inboxData.NumMessages != initialInboxCount-1 {
		t.Errorf("Expected %d messages in INBOX after move, got %d", initialInboxCount-1, inboxData.NumMessages)
	}

	// Verify message was moved to destination
	destData, err := c.Select(destMailbox, nil).Wait()
	if err != nil {
		t.Fatalf("Select destination mailbox failed: %v", err)
	}
	if destData.NumMessages != 1 {
		t.Errorf("Expected 1 message in destination mailbox, got %d", destData.NumMessages)
	}

	// Verify moved message retains flags
	fetchResults, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{
		Flags:    true,
		Envelope: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH from destination mailbox failed: %v", err)
	}

	if len(fetchResults) > 0 {
		flags := fetchResults[0].Flags
		subject := fetchResults[0].Envelope.Subject
		if !containsFlag(flags, imap.FlagSeen) {
			t.Error("\\Seen flag not preserved in moved message")
		}
		if !containsFlag(flags, imap.FlagImportant) {
			t.Error("\\Important flag not preserved in moved message")
		}
		if subject != "Move Test Message" {
			t.Errorf("Expected subject 'Move Test Message', got '%s'", subject)
		}
		t.Logf("Moved message - Subject: %s, Flags: %v", subject, flags)
	}

	t.Log("Move operations test completed successfully")
}
