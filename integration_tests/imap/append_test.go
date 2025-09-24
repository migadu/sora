//go:build integration

package imap_test

import (
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_AppendOperation tests various APPEND scenarios.
func TestIMAP_AppendOperation(t *testing.T) {
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

	t.Run("Simple Append", func(t *testing.T) {
		// Select INBOX to check initial state
		mbox, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		initialMessages := mbox.NumMessages

		// Append a simple message
		messageLiteral := "Subject: Simple Append Test\r\n\r\nThis is a test."
		appendCmd := c.Append("INBOX", int64(len(messageLiteral)), nil)
		if _, err := appendCmd.Write([]byte(messageLiteral)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND command failed: %v", err)
		}

		// Verify message count increased
		mbox, err = c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Reselect INBOX failed: %v", err)
		}
		if mbox.NumMessages != initialMessages+1 {
			t.Errorf("Expected %d messages, got %d", initialMessages+1, mbox.NumMessages)
		}
		t.Logf("Message count is now %d", mbox.NumMessages)

		// Fetch and verify the subject
		fetchCmd := c.Fetch(imap.SeqSetNum(mbox.NumMessages), &imap.FetchOptions{
			Envelope: true,
		})
		msgs, err := fetchCmd.Collect()
		if err != nil {
			t.Fatalf("FETCH failed: %v", err)
		}
		if len(msgs) != 1 {
			t.Fatalf("Expected 1 message, got %d", len(msgs))
		}
		if msgs[0].Envelope.Subject != "Simple Append Test" {
			t.Errorf("Expected subject 'Simple Append Test', got '%s'", msgs[0].Envelope.Subject)
		}
		t.Logf("Fetched message with correct subject: %s", msgs[0].Envelope.Subject)
	})

	t.Run("Append with Flags and Date", func(t *testing.T) {
		// Select INBOX to get current state
		mbox, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		initialMessages := mbox.NumMessages

		// Append a message with specific flags and internal date
		messageLiteral := "Subject: Flags and Date Test\r\n\r\nTesting flags."
		customDate := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
		appendCmd := c.Append("INBOX", int64(len(messageLiteral)), &imap.AppendOptions{
			Flags: []imap.Flag{imap.FlagSeen, imap.FlagFlagged},
			Time:  customDate,
		})
		if _, err := appendCmd.Write([]byte(messageLiteral)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND command failed: %v", err)
		}

		// Verify message count
		mbox, err = c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Reselect INBOX failed: %v", err)
		}
		if mbox.NumMessages != initialMessages+1 {
			t.Errorf("Expected %d messages, got %d", initialMessages+1, mbox.NumMessages)
		}

		// Fetch the new message and verify flags and date
		fetchCmd := c.Fetch(imap.SeqSetNum(mbox.NumMessages), &imap.FetchOptions{
			Flags:        true,
			InternalDate: true,
		})
		msgs, err := fetchCmd.Collect()
		if err != nil {
			t.Fatalf("FETCH failed: %v", err)
		}
		if len(msgs) != 1 {
			t.Fatalf("Expected 1 message, got %d", len(msgs))
		}
		msg := msgs[0]

		if !containsFlag(msg.Flags, imap.FlagSeen) {
			t.Error("Expected \\Seen flag, but not found")
		}
		if !containsFlag(msg.Flags, imap.FlagFlagged) {
			t.Error("Expected \\Flagged flag, but not found")
		}
		if !msg.InternalDate.Equal(customDate) {
			t.Errorf("Expected internal date %v, got %v", customDate, msg.InternalDate)
		}
		t.Logf("Fetched message with correct flags (%v) and date (%v)", msg.Flags, msg.InternalDate)
	})

	t.Run("Append to Non-Existent Mailbox", func(t *testing.T) {
		messageLiteral := "Subject: Failure Test\r\n\r\nThis should not be appended."
		appendCmd := c.Append("NonExistentMailbox", int64(len(messageLiteral)), nil)
		if _, err := appendCmd.Write([]byte(messageLiteral)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}

		_, err = appendCmd.Wait()
		if err == nil {
			t.Fatal("Expected APPEND to non-existent mailbox to fail, but it succeeded")
		}
		t.Logf("APPEND correctly failed for non-existent mailbox: %v", err)
	})

	t.Run("Append with Unicode Content", func(t *testing.T) {
		// Select INBOX to get current state
		mbox, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Select INBOX failed: %v", err)
		}
		initialMessages := mbox.NumMessages

		// Append a message with Unicode subject
		unicodeSubject := "Test: こんにちは世界"
		messageLiteral := "Subject: " + unicodeSubject + "\r\n\r\nUnicode body: ✅"
		appendCmd := c.Append("INBOX", int64(len(messageLiteral)), nil)
		if _, err := appendCmd.Write([]byte(messageLiteral)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND command failed: %v", err)
		}

		// Verify message count
		mbox, err = c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatalf("Reselect INBOX failed: %v", err)
		}
		if mbox.NumMessages != initialMessages+1 {
			t.Errorf("Expected %d messages, got %d", initialMessages+1, mbox.NumMessages)
		}

		// Fetch and verify the subject
		fetchCmd := c.Fetch(imap.SeqSetNum(mbox.NumMessages), &imap.FetchOptions{
			Envelope: true,
		})
		msgs, err := fetchCmd.Collect()
		if err != nil {
			t.Fatalf("FETCH failed: %v", err)
		}
		if len(msgs) != 1 {
			t.Fatalf("Expected 1 message, got %d", len(msgs))
		}
		if msgs[0].Envelope.Subject != unicodeSubject {
			t.Errorf("Expected subject '%s', got '%s'", unicodeSubject, msgs[0].Envelope.Subject)
		}
		t.Logf("Fetched message with correct Unicode subject: %s", msgs[0].Envelope.Subject)
	})
}
