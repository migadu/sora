//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_StatusRecent_ReflectsRecentMessages documents a KNOWN, ACCEPTED
// LIMITATION (audit finding H3, 2026-07-01): STATUS (RECENT) always reports 0.
//
// db/mailbox.go GetMailboxSummary never populates MailboxSummary.RecentCount.
// \Recent and the RECENT status item are OBSOLETE — removed in IMAP4rev2
// (RFC 9051) — and Sora is rev2-first. RECENT is meaningful only to legacy rev1
// clients, and Sora's per-session in-memory recent model has no well-defined
// cross-session value for STATUS on a (possibly non-selected) mailbox. We
// deliberately do NOT fix the value; this test is skipped and kept as executable
// documentation of the intended rev1 behavior should the decision change.
//
// (SELECT's NumRecent is computed on a separate path and IS correct; only the
// STATUS/LIST-STATUS RECENT item returns 0.)
//
// Expected if ever implemented (RFC 3501 §6.3.10): RECENT == 2 here.
func TestIMAP_StatusRecent_ReflectsRecentMessages(t *testing.T) {
	t.Skip("H3: STATUS (RECENT) always 0 — accepted rev1-compat limitation " +
		"(RECENT removed in IMAP4rev2; Sora is rev2-first). See memory " +
		"imap-command-correctness-audit-2026-07 (H3).")

	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Append 2 messages via the high-level client, never SELECTing INBOX.
	c, err := imapclient.DialInsecure(server.Address, nil)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	if err := c.Login(account.Email, account.Password).Wait(); err != nil {
		t.Fatalf("login failed: %v", err)
	}
	for i := 0; i < 2; i++ {
		msg := "From: sender@example.com\r\nTo: " + account.Email +
			"\r\nSubject: Recent Test\r\n\r\nbody\r\n"
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
	}
	c.Logout()

	// Raw STATUS: the rev2-first client refuses to request RECENT, so drive it
	// directly over the wire.
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

	if _, err := fmt.Fprintf(conn, "s1 STATUS INBOX (MESSAGES RECENT)\r\n"); err != nil {
		t.Fatalf("write STATUS failed: %v", err)
	}
	resp := h3ReadTagged(t, r, "s1")
	t.Logf("STATUS response:\n%s", strings.TrimRight(resp, "\r\n"))

	messages := h3ParseStatusItem(t, resp, "MESSAGES")
	recent := h3ParseStatusItem(t, resp, "RECENT")
	if messages != 2 {
		t.Fatalf("sanity: expected MESSAGES 2, got %d", messages)
	}
	if recent != messages {
		t.Errorf("REGRESSION: STATUS reported RECENT %d for a mailbox with %d never-SELECTed "+
			"messages; expected RECENT %d. MailboxSummary.RecentCount is never populated "+
			"(db/mailbox.go GetMailboxSummary).", recent, messages, messages)
	}
}

// h3ReadTagged accumulates response lines until a line beginning with "<tag> ".
func h3ReadTagged(t *testing.T, r *bufio.Reader, tag string) string {
	t.Helper()
	var sb strings.Builder
	for {
		line, err := r.ReadString('\n')
		if len(line) > 0 {
			sb.WriteString(line)
		}
		if err != nil {
			t.Fatalf("read until tag %q failed: %v (partial:\n%s)", tag, err, sb.String())
		}
		if strings.HasPrefix(line, tag+" ") {
			return sb.String()
		}
	}
}

func h3ParseStatusItem(t *testing.T, resp, item string) int {
	t.Helper()
	m := regexp.MustCompile(item + ` (\d+)`).FindStringSubmatch(resp)
	if m == nil {
		t.Fatalf("could not find STATUS item %q in response:\n%s", item, resp)
	}
	n, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("bad %s value %q: %v", item, m[1], err)
	}
	return n
}
