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

// TestIMAP_SearchModSeq_ClassicResponseHasTrailer is a regression test for a Medium audit
// finding (Unit 10, RFC 7162 §3.4).
//
// A classic (non-ESEARCH) "SEARCH MODSEQ ..." response MUST append the highest
// mod-sequence of the matched messages, e.g. "* SEARCH 1 (MODSEQ 917162500)".
// The fork's writeSearch only enumerated the numbers and dropped the trailer
// (the ESEARCH path emitted it). Sora computes data.ModSeq; the fork now emits it
// in writeSearch too, gated identically to writeESearch.
//
// The go-imap client only issues ESEARCH, so this is driven over the raw wire.
func TestIMAP_SearchModSeq_ClassicResponseHasTrailer(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Append a message so it gets a mod-sequence.
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	msg := "From: sender@example.com\r\nTo: " + account.Email +
		"\r\nSubject: MODSEQ Trailer Test\r\n\r\nbody\r\n"
	ac := c.Append("INBOX", int64(len(msg)), nil)
	if _, err := ac.Write([]byte(msg)); err != nil {
		t.Fatalf("APPEND write failed: %v", err)
	}
	if err := ac.Close(); err != nil {
		t.Fatalf("APPEND close failed: %v", err)
	}
	if _, err := ac.Wait(); err != nil {
		t.Fatalf("APPEND failed: %v", err)
	}
	c.Logout()

	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("raw dial failed: %v", err)
	}
	defer conn.Close()
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil { // greeting
		t.Fatalf("read greeting failed: %v", err)
	}

	if _, err := fmt.Fprintf(conn, "a1 LOGIN \"%s\" \"%s\"\r\n", account.Email, account.Password); err != nil {
		t.Fatalf("write LOGIN failed: %v", err)
	}
	if l := h3ReadTagged(t, r, "a1"); !strings.Contains(l, "OK") {
		t.Fatalf("LOGIN not OK:\n%s", l)
	}
	// SELECT (CONDSTORE) enables CONDSTORE awareness for this session.
	if _, err := fmt.Fprintf(conn, "a2 SELECT INBOX (CONDSTORE)\r\n"); err != nil {
		t.Fatalf("write SELECT failed: %v", err)
	}
	if l := h3ReadTagged(t, r, "a2"); !strings.Contains(l, "OK") {
		t.Fatalf("SELECT (CONDSTORE) not OK:\n%s", l)
	}
	// Classic SEARCH MODSEQ (no RETURN => non-ESEARCH path).
	if _, err := fmt.Fprintf(conn, "a3 SEARCH MODSEQ 1\r\n"); err != nil {
		t.Fatalf("write SEARCH failed: %v", err)
	}
	resp := h3ReadTagged(t, r, "a3")
	t.Logf("SEARCH response:\n%s", strings.TrimRight(resp, "\r\n"))

	if !strings.Contains(resp, "* SEARCH") {
		t.Fatalf("no untagged SEARCH response:\n%s", resp)
	}
	if !strings.Contains(resp, "(MODSEQ ") {
		t.Errorf("RFC 7162 §3.4: classic SEARCH MODSEQ response must append (MODSEQ n); got:\n%s", resp)
	}
}
