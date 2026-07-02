//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_StatusRecentGatedOnSessionRev2 verifies that STATUS (RECENT) gating
// follows the SESSION-enabled revision, not just the server-advertised one
// (fork imapserver/status.go, aligned with SELECT's rev2 gating).
//
// RECENT was removed in IMAP4rev2 (RFC 9051). On a server that advertises both
// rev1 and rev2:
//   - a session that has NOT enabled rev2 may still request STATUS (RECENT)
//     (rev1 backward compatibility) — accepted;
//   - a session that HAS enabled IMAP4rev2 must be told RECENT is unknown — BAD.
//
// Before the fix, STATUS gated only on the server advertising rev1, so a rev2
// session could still pull the obsolete RECENT item.
func TestIMAP_StatusRecentGatedOnSessionRev2(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

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
	if login := h3ReadTagged(t, r, "a1"); !strings.Contains(login, "OK") {
		t.Fatalf("LOGIN not OK:\n%s", login)
	}

	// Control: a rev1 (not-yet-rev2) session may still request RECENT.
	if _, err := fmt.Fprintf(conn, "s0 STATUS INBOX (MESSAGES RECENT)\r\n"); err != nil {
		t.Fatalf("write STATUS failed: %v", err)
	}
	pre := h3ReadTagged(t, r, "s0")
	if !strings.Contains(pre, "s0 OK") {
		t.Fatalf("rev1 session STATUS (RECENT) should be accepted, got:\n%s", pre)
	}
	if !strings.Contains(pre, "RECENT") {
		t.Fatalf("rev1 session STATUS (RECENT) response should carry a RECENT item, got:\n%s", pre)
	}

	// Enable IMAP4rev2 for the session.
	if _, err := fmt.Fprintf(conn, "e1 ENABLE IMAP4rev2\r\n"); err != nil {
		t.Fatalf("write ENABLE failed: %v", err)
	}
	if en := h3ReadTagged(t, r, "e1"); !strings.Contains(en, "OK") {
		t.Fatalf("ENABLE IMAP4rev2 not OK:\n%s", en)
	}

	// After enabling rev2, STATUS (RECENT) must be rejected as an unknown item.
	if _, err := fmt.Fprintf(conn, "s1 STATUS INBOX (MESSAGES RECENT)\r\n"); err != nil {
		t.Fatalf("write STATUS failed: %v", err)
	}
	post := h3ReadTagged(t, r, "s1")
	if !strings.Contains(post, "s1 BAD") {
		t.Errorf("rev2-enabled session STATUS (RECENT) should be rejected BAD, got:\n%s", post)
	}
}
