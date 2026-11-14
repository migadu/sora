//go:build integration

package imap_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_Examine_ReadOnly_RejectsStore is a regression test for audit finding H2
// (2026-07-01 IMAP command-correctness audit).
//
// RFC 3501 §6.3.2: "The EXAMINE command is identical to SELECT and returns the
// same output; however, the selected mailbox is identified as read-only. No
// changes to the permanent state of the mailbox ... are permitted."
//
// Sora computes but never stores/enforces a read-only mode for the selected
// mailbox. The go-imap STORE/EXPUNGE handlers only checkState(ConnStateSelected),
// and the mailbox owner holds every ACL right, so a STORE issued after EXAMINE
// mutates the mailbox instead of being rejected.
//
// Expected (RFC-correct): STORE after EXAMINE is rejected (tagged NO).
// Actual   (bug):         STORE succeeds and \Deleted is persisted.
//
// Fix: track the read-only selection mode (on the session or fork Conn, set from
// EXAMINE / SelectOptions.ReadOnly) and reject STORE/EXPUNGE with NO [READ-ONLY].
func TestIMAP_Examine_ReadOnly_RejectsStore(t *testing.T) {
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

	// APPEND a message to INBOX (authenticated state, no SELECT needed).
	msg := "From: sender@example.com\r\n" +
		"To: " + account.Email + "\r\n" +
		"Subject: Examine ReadOnly Test\r\n" +
		"\r\n" +
		"body\r\n"
	appendCmd := c.Append("INBOX", int64(len(msg)), nil)
	if _, err := appendCmd.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}

	// EXAMINE opens the mailbox read-only.
	sd, err := c.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		t.Fatalf("EXAMINE failed: %v", err)
	}
	if !sd.ReadOnly {
		t.Errorf("EXAMINE should report READ-ONLY on the tagged OK, got READ-WRITE")
	}

	// STORE must be rejected on a read-only (EXAMINE-opened) mailbox.
	_, storeErr := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Collect()

	if storeErr == nil {
		t.Errorf("REGRESSION: STORE succeeded on an EXAMINE-opened (read-only) mailbox; " +
			"RFC 3501 §6.3.2 requires it to be rejected (NO [READ-ONLY])")
	} else {
		t.Logf("STORE correctly rejected after EXAMINE: %v", storeErr)
	}
}

// TestIMAP_Examine_Close_Succeeds is a regression test for a bug reported by a
// JavaMail user: CLOSE after EXAMINE returned
//
//	NO [READ-ONLY] Mailbox is read-only (opened with EXAMINE)
//
// RFC 3501 §6.4.2: "No messages are removed, and no error is given, if the
// mailbox is selected by an EXAMINE command or is otherwise selected
// read-only." CLOSE must return tagged OK, skip the implicit expunge, and
// return the connection to the authenticated state.
//
// The failure came from go-imap's CLOSE handler unconditionally invoking the
// session Expunge hook, which (correctly) rejects expunge on a read-only
// mailbox; the fork now records the read-only selection on the connection and
// skips the expunge attempt for CLOSE.
func TestIMAP_Examine_Close_Succeeds(t *testing.T) {
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

	// APPEND two messages so we can prove CLOSE after EXAMINE removes nothing.
	for i := 0; i < 2; i++ {
		msg := "From: sender@example.com\r\n" +
			"To: " + account.Email + "\r\n" +
			"Subject: Examine Close Test\r\n" +
			"\r\n" +
			"body\r\n"
		appendCmd := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := appendCmd.Write([]byte(msg)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
	}

	// Flag a message \Deleted in a read-write session, then leave it pending:
	// re-selecting with EXAMINE implicitly unselects without expunging.
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}
	if _, err := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Collect(); err != nil {
		t.Fatalf("STORE \\Deleted failed: %v", err)
	}

	sd, err := c.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait()
	if err != nil {
		t.Fatalf("EXAMINE failed: %v", err)
	}
	if !sd.ReadOnly {
		t.Errorf("EXAMINE should report READ-ONLY on the tagged OK, got READ-WRITE")
	}

	// The reported bug: CLOSE after EXAMINE answered tagged NO [READ-ONLY].
	if err := c.UnselectAndExpunge().Wait(); err != nil {
		t.Fatalf("REGRESSION: CLOSE after EXAMINE failed, RFC 3501 §6.4.2 requires "+
			"tagged OK with no expunge: %v", err)
	}

	// The connection must be back in the authenticated state and the
	// \Deleted message must still exist (read-only CLOSE removes nothing).
	sd, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT after CLOSE failed (connection state desync?): %v", err)
	}
	if sd.NumMessages != 2 {
		t.Errorf("CLOSE after EXAMINE expunged messages: NumMessages = %d, want 2", sd.NumMessages)
	}

	// Sanity check the counterpart: CLOSE on a read-write SELECT does expunge.
	if err := c.UnselectAndExpunge().Wait(); err != nil {
		t.Fatalf("CLOSE after SELECT failed: %v", err)
	}
	sd, err = c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}
	if sd.NumMessages != 1 {
		t.Errorf("CLOSE after SELECT should have expunged the \\Deleted message: NumMessages = %d, want 1", sd.NumMessages)
	}
}

// TestIMAP_Examine_FetchDoesNotSetSeen: RFC 9051 §6.3.3 says of a mailbox
// opened with EXAMINE: "No changes to the permanent state of the mailbox,
// including per-user state, are permitted." FETCH BODY[] and BINARY[], which
// set \Seen in a read-write mailbox (§6.4.5), leave it alone there (#1041).
func TestIMAP_Examine_FetchDoesNotSetSeen(t *testing.T) {
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
	for range 2 {
		appendCmd := c.Append("INBOX", int64(len(binaryFetchTestMessage)), nil)
		if _, err := appendCmd.Write([]byte(binaryFetchTestMessage)); err != nil {
			t.Fatalf("APPEND write failed: %v", err)
		}
		if err := appendCmd.Close(); err != nil {
			t.Fatalf("APPEND close failed: %v", err)
		}
		if _, err := appendCmd.Wait(); err != nil {
			t.Fatalf("APPEND failed: %v", err)
		}
	}

	if _, err := c.Select("INBOX", &imap.SelectOptions{ReadOnly: true}).Wait(); err != nil {
		t.Fatalf("EXAMINE failed: %v", err)
	}
	bodySection := &imap.FetchItemBodySection{}
	binarySection := &imap.FetchItemBinarySection{Part: []int{1}}
	for _, tc := range []struct {
		name  string
		seq   uint32
		fetch *imap.FetchOptions
		data  func(*imapclient.FetchMessageBuffer) []byte
		want  string
	}{
		{"BODY[]", 1, &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{bodySection}},
			func(m *imapclient.FetchMessageBuffer) []byte { return m.FindBodySection(bodySection) }, binaryFetchTestMessage},
		{"BINARY[1]", 2, &imap.FetchOptions{BinarySection: []*imap.FetchItemBinarySection{binarySection}},
			func(m *imapclient.FetchMessageBuffer) []byte { return m.FindBinarySection(binarySection) }, "hello world"},
	} {
		msgs, err := c.Fetch(imap.SeqSetNum(tc.seq), tc.fetch).Collect()
		if err != nil {
			t.Fatalf("FETCH %d (%s) after EXAMINE failed: %v", tc.seq, tc.name, err)
		}
		// The FETCH still returns the data, and reports no flag change.
		if len(msgs) != 1 {
			t.Fatalf("FETCH %d (%s) after EXAMINE: got %d messages, want 1", tc.seq, tc.name, len(msgs))
		}
		if got := string(tc.data(msgs[0])); got != tc.want {
			t.Errorf("FETCH %d (%s) after EXAMINE returned %q, want %q", tc.seq, tc.name, got, tc.want)
		}
		if slices.Contains(msgs[0].Flags, imap.FlagSeen) {
			t.Errorf("FETCH %d (%s) after EXAMINE reported FLAGS %v", tc.seq, tc.name, msgs[0].Flags)
		}
	}

	// A read-write SELECT shows what the EXAMINE session left behind.
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("SELECT failed: %v", err)
	}
	msgs, err := c.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatalf("FETCH FLAGS failed: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("FETCH 1:2 (FLAGS): got %d messages, want 2", len(msgs))
	}
	for _, msg := range msgs {
		if slices.Contains(msg.Flags, imap.FlagSeen) {
			t.Errorf("message %d is \\Seen after a FETCH in a mailbox opened with EXAMINE", msg.SeqNum)
		}
	}
}

// TestIMAP_Examine_NotifyMessageNewDoesNotSetSeen: NOTIFY's MessageNew
// fetch-att list (RFC 5465 §5.2) is answered through FETCH, so a BODY[] there
// must not set \Seen in a mailbox opened with EXAMINE either (RFC 9051 §6.3.3).
func TestIMAP_Examine_NotifyMessageNewDoesNotSetSeen(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	login := fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)

	watcher := dialRawIMAP(t, server.Address)
	watcher.do(login)
	watcher.do("EXAMINE INBOX")
	watcher.do("NOTIFY SET (SELECTED (MessageNew (UID BODY[]) MessageExpunge))")

	other := dialRawIMAP(t, server.Address)
	other.do(login)
	other.appendMsg("INBOX", binaryFetchTestMessage)

	// The NOTIFY pump delivers asynchronously; NOOP collects what arrived.
	deadline := time.Now().Add(15 * time.Second)
	for {
		untagged, _ := watcher.do("NOOP")
		if resp := strings.Join(untagged, "\r\n"); strings.Contains(resp, "BODY[]") {
			if seenFlagsRe.MatchString(resp) {
				t.Errorf("NOTIFY MessageNew FETCH after EXAMINE reported \\Seen:\n%s", resp)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for the NOTIFY MessageNew FETCH (BODY[])")
		}
		time.Sleep(100 * time.Millisecond)
	}

	other.do("SELECT INBOX")
	if untagged, _ := other.do("FETCH 1 (FLAGS)"); seenFlagsRe.MatchString(strings.Join(untagged, "\r\n")) {
		t.Errorf("NOTIFY MessageNew FETCH (BODY[]) set \\Seen in a mailbox opened with EXAMINE: %v", untagged)
	}
}
