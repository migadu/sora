//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"

	imap "github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_StoreUnchangedSince_ModifiedUsesSequenceNumbers is a regression test for a
// Medium audit finding (Unit 10, RFC 7162 §3.1.3).
//
// When a conditional STORE fails the UNCHANGEDSINCE precondition, the server
// returns the failed messages in a MODIFIED response code. That set MUST use the
// command's number space: a UID STORE reports UIDs, but a *sequence-number* STORE
// must report sequence numbers. Sora accumulated failures into an imap.UIDSet and
// emitted UIDs unconditionally.
//
// We make sequence != UID by expunging UID 1 from a 3-message mailbox (leaving
// seq 1 = UID 2, seq 2 = UID 3), then issue a sequence-number STORE whose
// UNCHANGEDSINCE precondition fails for seq 1.
//
// Expected: OK [MODIFIED 1]  (sequence number).
// Actual (bug): the MODIFIED set reported UID 2 instead of sequence number 1.
func TestIMAP_StoreUnchangedSince_ModifiedUsesSequenceNumbers(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Append 3 messages (UIDs 1,2,3), then expunge UID 1 so seq 1 = UID 2.
	func() {
		c, err := imapclient.DialInsecure(server.Address, nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer c.Logout()
		if err := c.Login(account.Email, account.Password).Wait(); err != nil {
			t.Fatalf("login: %v", err)
		}
		for i := 0; i < 3; i++ {
			msg := "From: sender@example.com\r\nTo: " + account.Email +
				"\r\nSubject: MODSEQ SeqSpace Test\r\n\r\nbody\r\n"
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
		}
		if _, err := c.Select("INBOX", nil).Wait(); err != nil {
			t.Fatalf("select: %v", err)
		}
		if _, err := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{
			Op:    imap.StoreFlagsAdd,
			Flags: []imap.Flag{imap.FlagDeleted},
		}, nil).Collect(); err != nil {
			t.Fatalf("store \\Deleted: %v", err)
		}
		if _, err := c.Expunge().Collect(); err != nil {
			t.Fatalf("expunge: %v", err)
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
	// Sequence-number STORE on seq 1 (== UID 2). Its mod-sequence is > 1, so the
	// UNCHANGEDSINCE 1 precondition fails and the message goes into MODIFIED.
	if _, err := fmt.Fprintf(conn, "a3 STORE 1 (UNCHANGEDSINCE 1) +FLAGS (\\Flagged)\r\n"); err != nil {
		t.Fatalf("write STORE: %v", err)
	}
	resp := h3ReadTagged(t, r, "a3")
	t.Logf("STORE response:\n%s", strings.TrimRight(resp, "\r\n"))

	if !strings.Contains(resp, "MODIFIED") {
		t.Fatalf("expected a MODIFIED response for the failed UNCHANGEDSINCE STORE; got:\n%s", resp)
	}
	// RFC 7162 §3.1.3: the tagged response is OK (the STORE succeeded for passing
	// messages and skipped the changed one); NO is reserved for non-existent messages.
	if !strings.Contains(resp, "a3 OK") {
		t.Errorf("expected tagged OK [MODIFIED] for the failed-precondition STORE; got:\n%s", resp)
	}
	if strings.Contains(resp, "MODIFIED 2]") {
		t.Errorf("REGRESSION: sequence-number STORE reported the MODIFIED "+
			"set in UIDs ([MODIFIED 2] = UID); it must use sequence numbers ([MODIFIED 1]). Response:\n%s", resp)
	}
	if !strings.Contains(resp, "MODIFIED 1]") {
		t.Errorf("expected [MODIFIED 1] (sequence number) for the failed seq-number STORE; got:\n%s", resp)
	}
}
