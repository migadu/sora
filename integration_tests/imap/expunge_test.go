//go:build integration

package imap_test

import (
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_ExpungeOperations tests message expunge operations
func TestIMAP_ExpungeOperations(t *testing.T) {
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

	// Add multiple test messages
	for i := 1; i <= 3; i++ {
		testMessage := "From: expunge@example.com\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: Expunge Test Message " + string(rune('0'+i)) + "\r\n" +
			"Date: " + time.Now().Format(time.RFC1123) + "\r\n" +
			"\r\n" +
			"This is test message " + string(rune('0'+i)) + " for expunge operations.\r\n"

		appendCmd := c.Append("INBOX", int64(len(testMessage)), nil)
		_, err = appendCmd.Write([]byte(testMessage))
		if err != nil {
			t.Fatalf("APPEND write message %d failed: %v", i, err)
		}
		err = appendCmd.Close()
		if err != nil {
			t.Fatalf("APPEND close message %d failed: %v", i, err)
		}
		_, err = appendCmd.Wait()
		if err != nil {
			t.Fatalf("APPEND message %d failed: %v", i, err)
		}
	}

	// Verify we have 3 messages
	mbox, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX failed: %v", err)
	}
	if mbox.NumMessages != 3 {
		t.Errorf("Expected 3 messages, got %d", mbox.NumMessages)
	}
	t.Logf("Added 3 messages, total: %d", mbox.NumMessages)

	// Mark the second message for deletion
	storeCmd := c.Store(imap.SeqSetNum(2), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil)
	_, err = storeCmd.Collect()
	if err != nil {
		t.Fatalf("STORE \\Deleted flag failed: %v", err)
	}

	// Verify the message is marked as deleted
	fetchResults, err := c.Fetch(imap.SeqSetNum(2), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH after marking deleted failed: %v", err)
	}
	if len(fetchResults) == 0 {
		t.Fatal("FETCH returned no results")
	}

	if !containsFlag(fetchResults[0].Flags, imap.FlagDeleted) {
		t.Error("\\Deleted flag not found on marked message")
	}
	t.Log("Successfully marked message 2 as deleted")

	// Perform EXPUNGE
	expungeResults, err := c.Expunge().Collect()
	if err != nil {
		t.Fatalf("EXPUNGE failed: %v", err)
	}

	t.Logf("EXPUNGE results: %v", expungeResults)

	// Verify message count decreased
	mbox, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("Select INBOX after expunge failed: %v", err)
	}
	if mbox.NumMessages != 2 {
		t.Errorf("Expected 2 messages after expunge, got %d", mbox.NumMessages)
	}

	// Verify remaining messages are still accessible
	fetchResults, err = c.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{
		Envelope: true,
	}).Collect()
	if err != nil {
		t.Fatalf("FETCH after expunge failed: %v", err)
	}
	if len(fetchResults) != 2 {
		t.Errorf("Expected 2 messages after expunge, got %d", len(fetchResults))
	}

	t.Log("Expunge operations test completed successfully")
}
