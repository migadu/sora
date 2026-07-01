//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_UnsolicitedFetch_NoModseqWithoutCondstore reproduces the bug reported
// against Sora (and historically fixed in Dovecot v2.2.14): the server attaches a
// CONDSTORE MODSEQ data item to *unsolicited* FETCH responses even when the client
// never became CONDSTORE-aware.
//
// Per RFC 7162 §3.1 / §3.2, a client becomes "CONDSTORE-aware" only after issuing a
// CONDSTORE-enabling command (SELECT/EXAMINE ... (CONDSTORE), ENABLE CONDSTORE/QRESYNC,
// or a FETCH/SEARCH with MODSEQ/CHANGEDSINCE, or STORE with UNCHANGEDSINCE). A client
// that never does so must NOT be sent MODSEQ. mbsync/isync treats an unsolicited
// MODSEQ item as a malformed FETCH response and aborts the sync.
//
// Scenario (mirrors the field report):
//  1. A message exists in INBOX.
//  2. The "watcher" logs in and does a PLAIN `SELECT INBOX` — no CONDSTORE parameter,
//     no ENABLE, no MODSEQ FETCH modifier. It is NOT CONDSTORE-aware.
//  3. A second session changes a flag (STORE +FLAGS \Seen).
//  4. The watcher issues NOOP, triggering a poll that delivers an unsolicited FETCH.
//  5. That unsolicited FETCH must contain FLAGS but MUST NOT contain MODSEQ.
//
// Against the current code this assertion FAILS (MODSEQ is emitted), confirming the bug.
func TestIMAP_UnsolicitedFetch_NoModseqWithoutCondstore(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// 1. Seed a message into INBOX using a throwaway client.
	seedMessage(t, server, account)

	// 2. Watcher: raw TCP so we can inspect the exact bytes on the wire, exactly as
	//    mbsync would parse them. Plain SELECT — never becomes CONDSTORE-aware.
	watcher := dialRawIMAP(t, server.Address)
	watcher.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	watcher.do("SELECT INBOX")

	// 3. Modifier: a separate session flips a flag, generating a flag-change modseq.
	changeFlagFromAnotherSession(t, server, account)

	// 4. Watcher polls via NOOP and collects the unsolicited responses.
	untagged, _ := watcher.do("NOOP")

	// 5. Find the unsolicited FETCH carrying the flag change.
	fetchLine := findUnsolicitedFetch(untagged)
	if fetchLine == "" {
		// Guard against a false pass: if the poll delivered nothing, we haven't
		// actually exercised the code path.
		t.Fatalf("did not receive an unsolicited FETCH flag update after NOOP; got: %v", untagged)
	}
	t.Logf("unsolicited FETCH line: %q", fetchLine)

	if strings.Contains(fetchLine, "MODSEQ") {
		t.Errorf("BUG CONFIRMED: unsolicited FETCH contains MODSEQ for a client that never enabled CONDSTORE (RFC 7162 violation): %q", fetchLine)
	}
}

// TestIMAP_UnsolicitedFetch_ModseqWithCondstore is the positive control for the test
// above. It proves the wire-level detection is sound and that the presence/absence of
// MODSEQ is genuinely driven by CONDSTORE enablement: a client that DID enable CONDSTORE
// (via SELECT ... (CONDSTORE)) SHOULD receive MODSEQ in unsolicited FETCH updates
// (RFC 7162 §3.2). This test is expected to pass regardless of the bug fix.
func TestIMAP_UnsolicitedFetch_ModseqWithCondstore(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	seedMessage(t, server, account)

	watcher := dialRawIMAP(t, server.Address)
	watcher.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	// CONDSTORE-enabling SELECT: the watcher IS CONDSTORE-aware here.
	watcher.do("SELECT INBOX (CONDSTORE)")

	changeFlagFromAnotherSession(t, server, account)

	untagged, _ := watcher.do("NOOP")

	fetchLine := findUnsolicitedFetch(untagged)
	if fetchLine == "" {
		t.Fatalf("did not receive an unsolicited FETCH flag update after NOOP; got: %v", untagged)
	}
	t.Logf("unsolicited FETCH line: %q", fetchLine)

	if !strings.Contains(fetchLine, "MODSEQ") {
		t.Errorf("expected MODSEQ in unsolicited FETCH for a CONDSTORE-enabled client (RFC 7162 §3.2), got: %q", fetchLine)
	}
}

// findUnsolicitedFetch returns the first untagged FETCH line that carries a FLAGS item.
func findUnsolicitedFetch(untagged []string) string {
	for _, line := range untagged {
		if strings.HasPrefix(line, "* ") && strings.Contains(line, "FETCH") && strings.Contains(line, "FLAGS") {
			return line
		}
	}
	return ""
}

// seedMessage appends a single message to INBOX using a short-lived client so that
// sequence number 1 exists for the flag-change scenario.
func seedMessage(t *testing.T, server *common.TestServer, account common.TestAccount) {
	t.Helper()

	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial seed client: %v", err)
	}
	defer c.Logout()

	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Seed client login failed: %v", err)
	}

	msg := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Unsolicited MODSEQ Test\r\n\r\nBody.\r\n"
	appendCmd := c.Append("INBOX", int64(len(msg)), nil)
	if _, err := appendCmd.Write([]byte(msg)); err != nil {
		t.Fatalf("Failed to write append data: %v", err)
	}
	if err := appendCmd.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := appendCmd.Wait(); err != nil {
		t.Fatalf("APPEND wait failed: %v", err)
	}
}

// changeFlagFromAnotherSession logs in as the same account on a separate session and
// adds the \Seen flag to message 1, producing a flag-change modseq that will be
// delivered as an unsolicited FETCH to other selected sessions on their next poll.
func changeFlagFromAnotherSession(t *testing.T, server *common.TestServer, account common.TestAccount) {
	t.Helper()

	modifier, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("Failed to dial modifier client: %v", err)
	}
	defer modifier.Logout()
	if err := modifier.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("Modifier login failed: %v", err)
	}
	if _, err := modifier.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("Modifier SELECT failed: %v", err)
	}
	storeCmd := modifier.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagSeen},
	}, nil)
	if _, err := storeCmd.Collect(); err != nil {
		t.Fatalf("Modifier STORE failed: %v", err)
	}
}
