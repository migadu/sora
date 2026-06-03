//go:build integration

package imap_test

import (
	"testing"
	"time"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

func TestIMAP_Thread_Integration(t *testing.T) {
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

	// Create messages for the test:
	// Message 1 (UID 1): A base message
	// Message 2 (UID 2): Reply to Message 1
	// Message 3 (UID 3): Reply to Message 2
	// Message 4 (UID 4): A completely different message

	messages := []struct {
		body string
		date time.Time
	}{
		{
			body: "Message-ID: <msg1@example.com>\r\nSubject: Test Thread\r\n\r\nBase message",
			date: time.Now().Add(-4 * time.Hour),
		},
		{
			body: "Message-ID: <msg2@example.com>\r\nIn-Reply-To: <msg1@example.com>\r\nSubject: Re: Test Thread\r\n\r\nReply 1",
			date: time.Now().Add(-3 * time.Hour),
		},
		{
			body: "Message-ID: <msg3@example.com>\r\nIn-Reply-To: <msg2@example.com>\r\nSubject: Re: Test Thread\r\n\r\nReply 2",
			date: time.Now().Add(-2 * time.Hour),
		},
		{
			body: "Message-ID: <msg4@example.com>\r\nSubject: Unrelated\r\n\r\nDifferent thread",
			date: time.Now().Add(-1 * time.Hour),
		},
	}

	for _, msg := range messages {
		appendOpts := &imap.AppendOptions{Time: msg.date}
		appendCmd := c.Append("INBOX", int64(len(msg.body)), appendOpts)
		if _, err := appendCmd.Write([]byte(msg.body)); err != nil {
			t.Fatalf("Append write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("Append close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}

	t.Run("ORDEREDSUBJECT", func(t *testing.T) {
		opts := &imapclient.ThreadOptions{
			Algorithm:      imap.ThreadOrderedSubject,
			SearchCriteria: &imap.SearchCriteria{},
		}

		res, err := c.UIDThread(opts).Wait()
		if err != nil {
			t.Fatalf("UID THREAD ORDEREDSUBJECT failed: %v", err)
		}

		if len(res) != 2 {
			t.Fatalf("Expected 2 threads, got %d", len(res))
		}

		// First thread should be the "Test Thread" (UIDs 1, 2, 3)
		if len(res[0].Chain) != 3 {
			t.Errorf("Expected first thread to have 3 messages in chain, got %d", len(res[0].Chain))
		} else {
			if res[0].Chain[0] != 1 || res[0].Chain[1] != 2 || res[0].Chain[2] != 3 {
				t.Errorf("Expected chain [1 2 3], got %v", res[0].Chain)
			}
		}

		// Second thread should be "Unrelated" (UID 4)
		if len(res[1].Chain) != 1 || res[1].Chain[0] != 4 {
			t.Errorf("Expected second thread to have chain [4], got %v", res[1].Chain)
		}
	})

	t.Run("REFERENCES", func(t *testing.T) {
		opts := &imapclient.ThreadOptions{
			Algorithm:      imap.ThreadReferences,
			SearchCriteria: &imap.SearchCriteria{},
		}

		res, err := c.UIDThread(opts).Wait()
		if err != nil {
			t.Fatalf("UID THREAD REFERENCES failed: %v", err)
		}

		if len(res) != 2 {
			t.Fatalf("Expected 2 root threads, got %d", len(res))
		}

		// First thread: 1 -> 2 -> 3
		// Since it's a linear chain of replies (each has 1 child), the JWZ builder
		// should collapse them into a single Chain slice for efficiency.
		if len(res[0].Chain) != 3 {
			t.Errorf("Expected linear replies to collapse into chain of 3, got %d", len(res[0].Chain))
		}

		if len(res[1].Chain) != 1 || res[1].Chain[0] != 4 {
			t.Errorf("Expected second thread to have chain [4], got %v", res[1].Chain)
		}
	})

	t.Run("WITH_SEARCH_CRITERIA", func(t *testing.T) {
		// Test filtering using a body search (maps to messages_fts 'mc' alias)
		// and a flag search (maps to message_state 'ms' alias)
		opts := &imapclient.ThreadOptions{
			Algorithm: imap.ThreadReferences,
			SearchCriteria: &imap.SearchCriteria{
				NotFlag: []imap.Flag{imap.FlagDeleted}, // Requires ms alias to prove the SQL syntax is correct
			},
		}

		res, err := c.UIDThread(opts).Wait()
		if err != nil {
			t.Fatalf("UID THREAD WITH_SEARCH_CRITERIA failed: %v", err)
		}

		if len(res) != 2 {
			t.Fatalf("Expected 2 thread result, got %d", len(res))
		}

		if len(res[0].Chain) != 3 {
			t.Errorf("Expected first thread to have chain of 3, got %v", res[0].Chain)
		}
	})
}
