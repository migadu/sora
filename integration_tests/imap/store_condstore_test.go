//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestSTORE_CONDSTORE_ModifiedResponse verifies that a STORE with a stale
// UNCHANGEDSINCE returns a tagged OK [MODIFIED <set>] (RFC 7162 §3.1.3): the STORE
// succeeds for the messages that pass and reports the ones it skipped because
// their mod-sequence changed. (NO [MODIFIED] is reserved for the distinct case
// where targeted messages no longer exist.) A UID STORE reports UIDs.
//
// Driven over the raw wire: the go-imap client doesn't surface the MODIFIED
// response code on a tagged OK.
func TestSTORE_CONDSTORE_ModifiedResponse(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Append one message via the high-level client.
	func() {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Logout()
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("login: %v", err)
		}
		msg := "From: sender@example.com\r\nTo: " + account.Email +
			"\r\nSubject: CONDSTORE MODIFIED Test\r\n\r\nbody\r\n"
		ac := c.Append("INBOX", int64(len(msg)), nil)
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("append write: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("append close: %v", err)
		}
		if _, err := ac.Wait(); err != nil {
			t.Fatalf("append: %v", err)
		}
	}()

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil { // greeting
		t.Fatalf("greeting: %v", err)
	}
	if _, err := fmt.Fprintf(conn, "a1 LOGIN \"%s\" \"%s\"\r\n", account.Email, account.Password); err != nil {
		t.Fatalf("write LOGIN: %v", err)
	}
	if l := h3ReadTagged(t, r, "a1"); !strings.Contains(l, "OK") {
		t.Fatalf("LOGIN not OK:\n%s", l)
	}
	if _, err := fmt.Fprintf(conn, "a2 SELECT INBOX (CONDSTORE)\r\n"); err != nil {
		t.Fatalf("write SELECT: %v", err)
	}
	if l := h3ReadTagged(t, r, "a2"); !strings.Contains(l, "OK") {
		t.Fatalf("SELECT (CONDSTORE) not OK:\n%s", l)
	}
	// Bump UID 1's mod-sequence so a subsequent UNCHANGEDSINCE 1 fails.
	if _, err := fmt.Fprintf(conn, "a3 UID STORE 1 +FLAGS (\\Seen)\r\n"); err != nil {
		t.Fatalf("write first STORE: %v", err)
	}
	if l := h3ReadTagged(t, r, "a3"); !strings.Contains(l, "OK") {
		t.Fatalf("first STORE not OK:\n%s", l)
	}
	// Conditional UID STORE with a stale UNCHANGEDSINCE — the precondition fails.
	if _, err := fmt.Fprintf(conn, "a4 UID STORE 1 (UNCHANGEDSINCE 1) +FLAGS (\\Flagged)\r\n"); err != nil {
		t.Fatalf("write conditional STORE: %v", err)
	}
	resp := h3ReadTagged(t, r, "a4")
	t.Logf("conditional STORE response:\n%s", strings.TrimRight(resp, "\r\n"))

	// RFC 7162 §3.1.3: tagged OK (not NO), MODIFIED reporting the UID (UID STORE).
	if !strings.Contains(resp, "a4 OK") {
		t.Errorf("expected tagged OK for the failed-precondition STORE (RFC 7162 §3.1.3 — NO is only for "+
			"messages that no longer exist); got:\n%s", resp)
	}
	if !strings.Contains(resp, "[MODIFIED 1]") {
		t.Errorf("expected [MODIFIED 1] (UID) in the response; got:\n%s", resp)
	}
}
