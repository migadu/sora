//go:build integration

package imap_test

import (
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_RecentFlag_NotPersistentAcrossSessions verifies that the \Recent flag
// is NOT permanently stored and therefore not shown to a second session.
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

	// ── Session 2: completely independent connection ──────────────────────────
	c2, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("failed to dial (session 2): %v", err)
	}
	defer c2.Logout()

	if err := c2.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("session 2 login failed: %v", err)
	}

	mbox, err := c2.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("session 2 SELECT INBOX failed: %v", err)
	}
	t.Logf("session 2 INBOX: %d messages, NumRecent=%d", mbox.NumMessages, mbox.NumRecent)

	if mbox.NumMessages == 0 {
		t.Fatal("expected at least 1 message in INBOX")
	}

	// FETCH FLAGS for the appended message (by UID so no seqnum ambiguity)
	fetchResults, err := c2.Fetch(
		imap.UIDSetNum(appendData.UID),
		&imap.FetchOptions{Flags: true, UID: true},
	).Collect()
	if err != nil {
		t.Fatalf("session 2 FETCH failed: %v", err)
	}
	if len(fetchResults) == 0 {
		t.Fatal("session 2 FETCH returned no results")
	}

	flags := fetchResults[0].Flags
	t.Logf("session 2 FETCH FLAGS: %v", flags)

	// ── Assertion ─────────────────────────────────────────────────────────────
	// RFC 3501 §2.3.2: subsequent sessions MUST NOT see \Recent.
	// Before the fix: \Recent is stored permanently in the database bitfield, so
	// this assertion fails.
	recentFlag := imap.Flag("\\Recent")
	if containsFlag(flags, recentFlag) {
		t.Errorf("FAIL: \\Recent is set in session 2 – it must not be persistently stored in the database")
		t.Errorf("RFC 3501 §2.3.2: 'subsequent sessions MUST NOT see \\Recent set for this message'")
	} else {
		t.Log("PASS: \\Recent is NOT set in session 2 (correct per RFC 3501)")
	}
}

// TestIMAP_RecentFlag_CopyDoesNotStoreRecent verifies that messages copied to a
// destination mailbox do NOT have \Recent stored as a persistent flag.
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
	// Before the fix: CopyMessages ORs FlagRecent into all copied messages, so
	// the first assertion fails.
	recentFlag := imap.Flag("\\Recent")
	if containsFlag(flags, recentFlag) {
		t.Errorf("FAIL: \\Recent is stored on copied message – RFC 3501: \\Recent must not be a persistent flag")
	} else {
		t.Log("PASS: \\Recent is NOT set on copied message (correct per RFC 3501)")
	}

	// Source \Seen flag must survive the COPY.
	if !containsFlag(flags, imap.FlagSeen) {
		t.Errorf("FAIL: \\Seen flag was NOT preserved during COPY")
	}
}
