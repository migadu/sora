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

// TestIMAP_QResync_LiveExpunge_ReportsVanished is a regression test for a Medium audit
// finding (Unit 10, RFC 7162 §3.2.10).
//
// Once a client has enabled QRESYNC, the server must report expunged messages
// with VANISHED responses instead of EXPUNGE. Previously the fork's tracker Poll
// always emitted "* n EXPUNGE" for live expunges, even to QRESYNC-enabled
// sessions (VANISHED only appeared on the SELECT-resync path).
//
// A QRESYNC session B watches INBOX while a separate session A expunges a
// message; B's next poll must deliver "* VANISHED <uid>", not "* n EXPUNGE".
//
// Driven over the raw wire (the go-imap client's Expunge command is
// sequence-number oriented; VANISHED arrives via the unilateral path).
func TestIMAP_QResync_LiveExpunge_ReportsVanished(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Session A: append 2 messages to INBOX (uids 1 and 2).
	cA, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("A dial failed: %v", err)
	}
	defer cA.Logout()
	if err := cA.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("A login failed: %v", err)
	}
	for i := 0; i < 2; i++ {
		msg := "From: sender@example.com\r\nTo: " + account.Email +
			"\r\nSubject: QRESYNC Vanished Test\r\n\r\nbody\r\n"
		ac := cA.Append("INBOX", int64(len(msg)), nil)
		if _, err := ac.Write([]byte(msg)); err != nil {
			t.Fatalf("A APPEND write failed: %v", err)
		}
		if err := ac.Close(); err != nil {
			t.Fatalf("A APPEND close failed: %v", err)
		}
		if _, err := ac.Wait(); err != nil {
			t.Fatalf("A APPEND failed: %v", err)
		}
	}

	// Session B (raw): enable QRESYNC and select INBOX so it watches for updates.
	connB, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("B dial failed: %v", err)
	}
	defer connB.Close()
	rB := bufio.NewReader(connB)
	if _, err := rB.ReadString('\n'); err != nil { // greeting
		t.Fatalf("B greeting failed: %v", err)
	}
	if _, err := fmt.Fprintf(connB, "b1 LOGIN \"%s\" \"%s\"\r\n", account.Email, account.Password); err != nil {
		t.Fatalf("B write LOGIN failed: %v", err)
	}
	if l := h3ReadTagged(t, rB, "b1"); !strings.Contains(l, "OK") {
		t.Fatalf("B LOGIN not OK:\n%s", l)
	}
	if _, err := fmt.Fprintf(connB, "b2 ENABLE QRESYNC\r\n"); err != nil {
		t.Fatalf("B write ENABLE failed: %v", err)
	}
	if l := h3ReadTagged(t, rB, "b2"); !strings.Contains(l, "OK") {
		t.Fatalf("B ENABLE QRESYNC not OK:\n%s", l)
	}
	if _, err := fmt.Fprintf(connB, "b3 SELECT INBOX\r\n"); err != nil {
		t.Fatalf("B write SELECT failed: %v", err)
	}
	if l := h3ReadTagged(t, rB, "b3"); !strings.Contains(l, "OK") {
		t.Fatalf("B SELECT INBOX not OK:\n%s", l)
	}

	// Session A: expunge uid 1.
	if _, err := cA.Select("INBOX", nil).Wait(); err != nil {
		t.Fatalf("A SELECT failed: %v", err)
	}
	if _, err := cA.Store(imap.SeqSetNum(1), &imap.StoreFlags{
		Op:    imap.StoreFlagsAdd,
		Flags: []imap.Flag{imap.FlagDeleted},
	}, nil).Collect(); err != nil {
		t.Fatalf("A STORE \\Deleted failed: %v", err)
	}
	if _, err := cA.Expunge().Collect(); err != nil {
		t.Fatalf("A EXPUNGE failed: %v", err)
	}

	// Session B: poll (NOOP) — must receive VANISHED, not EXPUNGE, for the live expunge.
	if _, err := fmt.Fprintf(connB, "b4 NOOP\r\n"); err != nil {
		t.Fatalf("B write NOOP failed: %v", err)
	}
	resp := h3ReadTagged(t, rB, "b4")
	t.Logf("B NOOP response:\n%s", strings.TrimRight(resp, "\r\n"))

	if strings.Contains(resp, "EXPUNGE") {
		t.Errorf("REGRESSION: QRESYNC session received EXPUNGE for a live expunge; "+
			"RFC 7162 §3.2.10 requires VANISHED. Response:\n%s", resp)
	}
	if !strings.Contains(resp, "VANISHED") {
		t.Errorf("expected a VANISHED response for the live expunge on a QRESYNC session; got:\n%s", resp)
	}
}
