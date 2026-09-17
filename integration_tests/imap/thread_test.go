//go:build integration

package imap_test

import (
	"fmt"
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
		{
			body: "Message-ID: <msg5@example.com>\r\nSubject: Test Thread\r\n\r\nDisconnected but same subject",
			date: time.Now(),
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

		// First thread should be the "Test Thread" (UIDs 1, 2, 3) AND 5 (since it shares the subject)
		if len(res[0].Chain) != 4 {
			t.Errorf("Expected first thread to have 4 messages in chain, got %d", len(res[0].Chain))
		} else {
			if res[0].Chain[0] != 1 || res[0].Chain[1] != 2 || res[0].Chain[2] != 3 || res[0].Chain[3] != 5 {
				t.Errorf("Expected chain [1 2 3 5], got %v", res[0].Chain)
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
		// However, Message 5 shares the subject "Test Thread", so it MUST be grouped into this thread under a dummy node.
		if len(res[0].Chain) != 0 {
			t.Errorf("Expected dummy root node (empty chain), got %v", res[0].Chain)
		}
		if len(res[0].SubThreads) != 2 {
			t.Fatalf("Expected 2 subthreads under dummy node, got %d", len(res[0].SubThreads))
		}

		// SubThread 0: The linear chain 1->2->3
		if len(res[0].SubThreads[0].Chain) != 3 {
			t.Errorf("Expected linear replies to collapse into chain of 3, got %d", len(res[0].SubThreads[0].Chain))
		}
		// SubThread 1: The isolated message 5 that was grouped by subject
		if len(res[0].SubThreads[1].Chain) != 1 || res[0].SubThreads[1].Chain[0] != 5 {
			t.Errorf("Expected message 5 as second subthread, got %v", res[0].SubThreads[1].Chain)
		}

		if len(res[1].Chain) != 1 || res[1].Chain[0] != 4 {
			t.Errorf("Expected second thread to have chain [4], got %v", res[1].Chain)
		}
	})

	t.Run("REFS", func(t *testing.T) {
		opts := &imapclient.ThreadOptions{
			Algorithm:      imap.ThreadRefs,
			SearchCriteria: &imap.SearchCriteria{},
		}

		res, err := c.UIDThread(opts).Wait()
		if err != nil {
			t.Fatalf("UID THREAD REFS failed: %v", err)
		}

		// REFS explicitly skips Subject Grouping.
		// Therefore, Message 5 (which has the same subject but no ID link) MUST be placed in its own root thread!
		if len(res) != 3 {
			t.Fatalf("Expected 3 root threads for REFS, got %d", len(res))
		}

		// First thread: 1 -> 2 -> 3 (Linked by IDs)
		if len(res[0].Chain) != 3 {
			t.Errorf("Expected linear replies to collapse into chain of 3, got %d", len(res[0].Chain))
		}

		// Second thread: 4 (Isolated message)
		if len(res[1].Chain) != 1 || res[1].Chain[0] != 4 {
			t.Errorf("Expected thread for msg 4, got %v", res[1].Chain)
		}

		// Third thread: 5 (Isolated message, NOT grouped with 1,2,3)
		if len(res[2].Chain) != 1 || res[2].Chain[0] != 5 {
			t.Errorf("Expected thread for msg 5, got %v", res[2].Chain)
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

		if len(res[0].Chain) != 0 {
			t.Errorf("Expected dummy root node (empty chain), got %v", res[0].Chain)
		}
		if len(res[0].SubThreads) != 2 {
			t.Fatalf("Expected 2 subthreads, got %d", len(res[0].SubThreads))
		}
	})
}

// TestIMAP_Thread_ReferencesHeaders threads messages the way mail clients write
// them: a References line naming the whole ancestry, a parent that is not in the
// mailbox (the user's own reply, filed in Sent), and a message with no Message-ID.
func TestIMAP_Thread_ReferencesHeaders(t *testing.T) {
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

	// Subjects differ throughout, so only the references can join UIDs 1-3.
	start := time.Now().Add(-4 * time.Hour)
	for i, body := range []string{
		"Message-ID: <q@example.com>\r\nSubject: Question\r\n\r\nAsking",
		"Message-ID: <r2@example.com>\r\nIn-Reply-To: <mine@example.com>\r\n" +
			"References: <q@example.com> <mine@example.com>\r\nSubject: Answer\r\n\r\nAnswering the reply in Sent",
		"Message-ID: <r3@example.com>\r\nIn-Reply-To: <r2@example.com>\r\n" +
			"References: <q@example.com>\r\n <mine@example.com> <r2@example.com>\r\nSubject: Something else\r\n\r\nFolded References",
		"Subject: No id\r\n\r\nNo Message-ID at all",
	} {
		appendCmd := c.Append("INBOX", int64(len(body)), &imap.AppendOptions{Time: start.Add(time.Duration(i) * time.Hour)})
		if _, err := appendCmd.Write([]byte(body)); err != nil {
			t.Fatalf("Append write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("Append close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("Append %d failed: %v", i+1, err)
		}
	}

	for _, alg := range []imap.ThreadAlgorithm{imap.ThreadReferences, imap.ThreadRefs} {
		t.Run(string(alg), func(t *testing.T) {
			res, err := c.UIDThread(&imapclient.ThreadOptions{
				Algorithm:      alg,
				SearchCriteria: &imap.SearchCriteria{},
			}).Wait()
			if err != nil {
				t.Fatalf("UID THREAD %s failed: %v", alg, err)
			}
			if len(res) != 2 {
				t.Fatalf("Expected 2 threads, got %d: %+v", len(res), res)
			}
			if got := res[0].Chain; len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
				t.Errorf("Expected first thread [1 2 3], got %+v", res[0])
			}
			if got := res[1].Chain; len(got) != 1 || got[0] != 4 {
				t.Errorf("Expected second thread [4], got %+v", res[1])
			}
		})
	}
}

// TestIMAP_Thread_EveryAlgorithmAdvertised checks that each algorithm THREAD
// accepts is in CAPABILITY: a client only uses the ones it is offered.
func TestIMAP_Thread_EveryAlgorithmAdvertised(t *testing.T) {
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
	caps, err := c.Capability().Wait()
	if err != nil {
		t.Fatalf("CAPABILITY failed: %v", err)
	}

	advertised := caps.ThreadAlgorithms()
	for _, want := range []imap.ThreadAlgorithm{imap.ThreadOrderedSubject, imap.ThreadReferences, imap.ThreadRefs} {
		found := false
		for _, alg := range advertised {
			found = found || alg == want
		}
		if !found {
			t.Errorf("THREAD=%s not advertised; advertised: %v", want, advertised)
		}
	}
}

// TestIMAP_Thread_RefsOrdersByLatestArrival: under REFS a thread moves to the
// end when mail arrives in it, whatever the message says its sent date is;
// REFERENCES keeps ordering threads by their first message.
func TestIMAP_Thread_RefsOrdersByLatestArrival(t *testing.T) {
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

	// APPEND's date-time is the INTERNALDATE; Date: is the sent date.
	now := time.Now()
	for i, m := range []struct {
		body    string
		arrived time.Time
	}{
		{"Message-ID: <old@example.com>\r\nDate: " + now.Add(-5*time.Hour).Format(time.RFC1123Z) +
			"\r\nSubject: Old question\r\n\r\nAsked long ago", now.Add(-5 * time.Hour)},
		{"Message-ID: <other@example.com>\r\nDate: " + now.Add(-4*time.Hour).Format(time.RFC1123Z) +
			"\r\nSubject: Unrelated\r\n\r\nIn between", now.Add(-4 * time.Hour)},
		{"Message-ID: <late@example.com>\r\nIn-Reply-To: <old@example.com>\r\nReferences: <old@example.com>\r\nDate: " +
			now.Add(-4*time.Hour).Format(time.RFC1123Z) + "\r\nSubject: Late answer\r\n\r\nArrived just now", now.Add(-time.Minute)},
	} {
		appendCmd := c.Append("INBOX", int64(len(m.body)), &imap.AppendOptions{Time: m.arrived})
		if _, err := appendCmd.Write([]byte(m.body)); err != nil {
			t.Fatalf("Append write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("Append close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("Append %d failed: %v", i+1, err)
		}
	}

	thread := func(alg imap.ThreadAlgorithm) []imap.ThreadData {
		t.Helper()
		res, err := c.UIDThread(&imapclient.ThreadOptions{Algorithm: alg, SearchCriteria: &imap.SearchCriteria{}}).Wait()
		if err != nil {
			t.Fatalf("UID THREAD %s failed: %v", alg, err)
		}
		if len(res) != 2 {
			t.Fatalf("UID THREAD %s: expected 2 threads, got %+v", alg, res)
		}
		return res
	}
	chains := func(res []imap.ThreadData) string {
		return fmt.Sprint(res[0].Chain, res[1].Chain)
	}

	if got, want := chains(thread(imap.ThreadRefs)), "[2] [1 3]"; got != want {
		t.Errorf("REFS order = %s, want %s: the thread that just received mail must come last", got, want)
	}
	if got, want := chains(thread(imap.ThreadReferences)), "[1 3] [2]"; got != want {
		t.Errorf("REFERENCES order = %s, want %s", got, want)
	}
}
