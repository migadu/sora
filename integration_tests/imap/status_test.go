//go:build integration

package imap_test

import (
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_ComprehensiveMailboxStatus tests comprehensive STATUS operations
func TestIMAP_ComprehensiveMailboxStatus(t *testing.T) {
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

	// Test 1: STATUS on empty INBOX
	statusData, err := c.Status("INBOX", &imap.StatusOptions{
		NumMessages:   true,
		NumUnseen:     true,
		UIDNext:       true,
		UIDValidity:   true,
		HighestModSeq: true,
	}).Wait()
	if err != nil {
		t.Fatalf("STATUS command failed: %v", err)
	}

	if statusData.Mailbox != "INBOX" {
		t.Errorf("Expected mailbox INBOX, got %s", statusData.Mailbox)
	}

	if statusData.NumMessages != nil && *statusData.NumMessages != 0 {
		t.Errorf("Expected 0 messages in empty INBOX, got %d", *statusData.NumMessages)
	}

	if statusData.NumUnseen != nil && *statusData.NumUnseen != 0 {
		t.Errorf("Expected 0 unseen messages in empty INBOX, got %d", *statusData.NumUnseen)
	}

	t.Logf("Empty INBOX status - Messages: %v, Unseen: %v, UIDNext: %d, UIDValidity: %d, HighestModSeq: %d",
		statusData.NumMessages, statusData.NumUnseen, statusData.UIDNext, statusData.UIDValidity, statusData.HighestModSeq)

	// Add some messages to test with
	testMessage1 := "From: test1@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Status Test Message 1\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"First test message for status testing.\r\n"

	testMessage2 := "From: test2@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Status Test Message 2\r\n" +
		"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
		"\r\n" +
		"Second test message for status testing.\r\n"

	// Append first message with \Seen flag
	appendCmd1 := c.Append("INBOX", int64(len(testMessage1)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen},
		Time:  time.Now(),
	})
	_, err = appendCmd1.Write([]byte(testMessage1))
	if err != nil {
		t.Fatalf("APPEND write first message failed: %v", err)
	}
	err = appendCmd1.Close()
	if err != nil {
		t.Fatalf("APPEND close first message failed: %v", err)
	}
	_, err = appendCmd1.Wait()
	if err != nil {
		t.Fatalf("APPEND first message failed: %v", err)
	}

	// Append second message without \Seen flag (unseen)
	appendCmd2 := c.Append("INBOX", int64(len(testMessage2)), &imap.AppendOptions{
		Flags: []imap.Flag{},
		Time:  time.Now(),
	})
	_, err = appendCmd2.Write([]byte(testMessage2))
	if err != nil {
		t.Fatalf("APPEND write second message failed: %v", err)
	}
	err = appendCmd2.Close()
	if err != nil {
		t.Fatalf("APPEND close second message failed: %v", err)
	}
	_, err = appendCmd2.Wait()
	if err != nil {
		t.Fatalf("APPEND second message failed: %v", err)
	}

	// Test 2: STATUS after adding messages
	statusData, err = c.Status("INBOX", &imap.StatusOptions{
		NumMessages:   true,
		NumUnseen:     true,
		UIDNext:       true,
		UIDValidity:   true,
		HighestModSeq: true,
	}).Wait()
	if err != nil {
		t.Fatalf("STATUS command after adding messages failed: %v", err)
	}

	if statusData.NumMessages != nil && *statusData.NumMessages != 2 {
		t.Errorf("Expected 2 messages after adding, got %d", *statusData.NumMessages)
	}

	if statusData.NumUnseen != nil && *statusData.NumUnseen != 1 {
		t.Errorf("Expected 1 unseen message after adding, got %d", *statusData.NumUnseen)
	}

	t.Logf("INBOX status after adding messages - Messages: %d, Unseen: %d, UIDNext: %d, UIDValidity: %d, HighestModSeq: %d",
		statusData.NumMessages, statusData.NumUnseen, statusData.UIDNext, statusData.UIDValidity, statusData.HighestModSeq)

	// Test 3: STATUS with selective options
	statusData, err = c.Status("INBOX", &imap.StatusOptions{
		NumMessages: true,
		UIDNext:     true,
	}).Wait()
	if err != nil {
		t.Fatalf("STATUS with selective options failed: %v", err)
	}

	// Only requested fields should be populated
	if statusData.NumMessages == nil {
		t.Error("NumMessages should be populated when requested")
	}
	if statusData.UIDNext == 0 {
		t.Error("UIDNext should be populated when requested")
	}
	t.Logf("Selective STATUS - Messages: %v, UIDNext: %d", statusData.NumMessages, statusData.UIDNext)

	// Test 4: STATUS on non-existent mailbox (should fail)
	_, err = c.Status("NonExistentMailbox", &imap.StatusOptions{
		NumMessages: true,
	}).Wait()
	if err == nil {
		t.Error("STATUS on non-existent mailbox should fail")
	} else {
		t.Logf("STATUS correctly failed on non-existent mailbox: %v", err)
	}

	t.Log("Comprehensive mailbox status test completed successfully")
}
