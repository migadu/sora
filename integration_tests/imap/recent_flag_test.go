//go:build integration

package imap_test

import (
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_RecentFlag_NotPersistentAcrossSessions verifies that the \Recent flag
// is NOT permanently stored: the first session to select the mailbox sees it,
// the next one does not.
//
// RFC 3501 §2.3.2: "This session is the first session to have been notified about
// this message; if the session is read-write, subsequent sessions will not see
// \Recent set for this message. This flag can not be altered by the client."
//
// The bug: the server appends \Recent to the persistent bitwise flags in the
// database on every APPEND/COPY, so every future session's FETCH FLAGS response
// permanently includes \Recent.
func TestIMAP_RecentFlag_NotPersistentAcrossSessions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// ── Session 1: append a message without selecting the mailbox ────────────
	c1, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("failed to dial (session 1): %v", err)
	}
	if err := c1.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("session 1 login failed: %v", err)
	}

	msg := "From: sender@example.com\r\nTo: " + account.Email +
		"\r\nSubject: Recent Flag Test\r\n\r\nBody of recent-flag test."

	appendCmd := c1.Append("INBOX", int64(len(msg)), nil)
	if _, err := appendCmd.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	appendData, err := appendCmd.Wait()
	if err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}
	t.Logf("session 1 appended UID %d", appendData.UID)
	_ = c1.Logout()

	// ── Sessions 2 and 3: independent connections that SELECT INBOX in turn ──
	// Session 1 never selected INBOX, so session 2 is the first session to be
	// notified of the message and sees it \Recent. After its read-write SELECT,
	// session 3 must not (RFC 3501 §2.3.2).
	for _, tc := range []struct {
		session    int
		wantRecent bool
	}{{2, true}, {3, false}} {
		flags := selectAndFetchFlags(t, server.Address, account, "INBOX", appendData.UID)
		t.Logf("session %d FETCH FLAGS: %v", tc.session, flags)
		if got := containsFlag(flags, imap.Flag("\\Recent")); got != tc.wantRecent {
			t.Errorf("session %d: \\Recent in FETCH FLAGS = %v, want %v (RFC 3501 §2.3.2)", tc.session, got, tc.wantRecent)
		}
	}
}

// selectAndFetchFlags logs in on a new connection, selects mbox read-write and
// returns the FETCH FLAGS of message uid there. The connection stays open, with
// mbox selected, until the test ends.
func selectAndFetchFlags(t *testing.T, addr string, account common.TestAccount, mbox string, uid imap.UID) []imap.Flag {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Logout() })
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := c.Select(mbox, nil).Wait(); err != nil {
		t.Fatalf("SELECT %s: %v", mbox, err)
	}
	msgs, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{Flags: true, UID: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH UID %d FLAGS in %s: %v", uid, mbox, err)
	}
	if len(msgs) != 1 {
		t.Fatalf("FETCH UID %d FLAGS in %s returned %d messages, want 1", uid, mbox, len(msgs))
	}
	return msgs[0].Flags
}

// TestIMAP_RecentFlag_CopyDoesNotStoreRecent verifies that messages copied to a
// destination mailbox do NOT have \Recent stored as a persistent flag: the
// session that selects the destination first sees the copy \Recent (RFC 3501
// §6.4.7: "the Recent flag SHOULD be set, in the copy"), a later session
// does not.
//
// The bug: CopyMessages in db/append.go ORs FlagRecent into the flags of every
// copied message, making it a permanent stored flag.
//
// We use "Sent" as the destination because it is guaranteed to exist as a default
// mailbox. This avoids the need to create a new mailbox and lets us focus purely
// on the \Recent flag invariant.
func TestIMAP_RecentFlag_CopyDoesNotStoreRecent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}

	// Select INBOX first so the session is in a known state, then append a
	// message with only \Seen (no \Recent).
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT INBOX failed: %v", err)
	}

	msg := "From: sender@example.com\r\nSubject: Copy Recent Test\r\n\r\nBody."
	appendCmd := c.Append("INBOX", int64(len(msg)), &imap.AppendOptions{
		Flags: []imap.Flag{imap.FlagSeen},
	})
	if _, err := appendCmd.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// Re-select INBOX to refresh the message count after APPEND.
	inboxData, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("re-SELECT INBOX failed: %v", err)
	}
	if inboxData.NumMessages == 0 {
		t.Fatal("expected at least 1 message in INBOX after APPEND")
	}

	// Copy to "Sent" — always exists as a default mailbox, no CREATE required.
	// This is equivalent to what Thunderbird does when dragging messages between folders.
	copyData, err := c.Copy(imap.SeqSetNum(inboxData.NumMessages), "Sent").Wait()
	if err != nil {
		t.Fatalf("COPY to Sent failed: %v", err)
	}
	destUID := copyData.UIDMapping[0].Dest.Start
	t.Logf("COPY succeeded, dest UID %d in Sent", destUID)

	// Select Sent and fetch the copied message's flags via UID.
	if _, err := c.Select("Sent", nil).Wait(); err != nil {
		t.Fatalf("SELECT Sent failed: %v", err)
	}
	fetchResults, err := c.Fetch(
		imap.UIDSetNum(destUID),
		&imap.FetchOptions{Flags: true, UID: true},
	).Collect()
	if err != nil {
		t.Fatalf("FETCH failed: %v", err)
	}
	if len(fetchResults) == 0 {
		t.Fatal("FETCH returned no results for copied message in Sent")
	}

	flags := fetchResults[0].Flags
	t.Logf("copied message flags in Sent: %v", flags)

	// ── Assertions ────────────────────────────────────────────────────────────
	// This session is the first to select Sent since the copy arrived, so the
	// copy is \Recent here; the next session must not see it \Recent. Before
	// the fix: CopyMessages ORs FlagRecent into all copied messages, so the
	// second session sees it too.
	recentFlag := imap.Flag("\\Recent")
	if !containsFlag(flags, recentFlag) {
		t.Errorf("copied message is not \\Recent in the first session to select Sent: %v", flags)
	}
	if later := selectAndFetchFlags(t, server.Address, account, "Sent", destUID); containsFlag(later, recentFlag) {
		t.Errorf("\\Recent is stored on copied message, a later session sees it: %v", later)
	}

	// Source \Seen flag must survive the COPY.
	if !containsFlag(flags, imap.FlagSeen) {
		t.Errorf("FAIL: \\Seen flag was NOT preserved during COPY")
	}
}
