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

// TestIMAP_StoreUnchangedSinceZero_FailsEveryMessage covers the always-fail probe
// of RFC 7162 §3.1.3.1: "UNCHANGEDSINCE 0" can never be satisfied, because every
// message's mod-sequence is greater than zero.
//
// An absent modifier and an explicit zero mean opposite things — store
// unconditionally, versus store nothing — and the value alone cannot tell them
// apart. Reading the modifier as absent whenever it was zero therefore inverted
// the request, modifying exactly the messages the client asked never to touch.
func TestIMAP_StoreUnchangedSinceZero_FailsEveryMessage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

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
			"\r\nSubject: UNCHANGEDSINCE 0 Test\r\n\r\nbody\r\n"
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

	if _, err := fmt.Fprintf(conn, "a3 STORE 1 (UNCHANGEDSINCE 0) +FLAGS (\\Flagged)\r\n"); err != nil {
		t.Fatalf("write STORE: %v", err)
	}
	resp := h3ReadTagged(t, r, "a3")
	t.Logf("STORE response:\n%s", strings.TrimRight(resp, "\r\n"))

	if !strings.Contains(resp, "MODIFIED") {
		t.Errorf("UNCHANGEDSINCE 0 must fail for every message and report them in MODIFIED; got:\n%s", resp)
	}
	if !strings.Contains(resp, "a3 OK") {
		t.Errorf("expected tagged OK [MODIFIED] (NO is reserved for messages that no longer exist); got:\n%s", resp)
	}

	// The flag must not have been applied.
	if _, err := fmt.Fprintf(conn, "a4 FETCH 1 (FLAGS)\r\n"); err != nil {
		t.Fatalf("write FETCH: %v", err)
	}
	fetched := h3ReadTagged(t, r, "a4")
	t.Logf("FETCH response:\n%s", strings.TrimRight(fetched, "\r\n"))
	if strings.Contains(fetched, "\\Flagged") {
		t.Errorf("STORE (UNCHANGEDSINCE 0) modified the message it was told never to touch; FLAGS:\n%s", fetched)
	}
}
