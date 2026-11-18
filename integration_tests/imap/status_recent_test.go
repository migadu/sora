//go:build integration

package imap_test

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_StatusRecent_ReflectsRecentMessages: STATUS (RECENT) of a mailbox
// that no session has selected read-write counts every message (RFC 3501
// §6.3.10, §2.3.2). RECENT is an IMAP4rev1 item (removed in IMAP4rev2, RFC 9051
// Appendix E), so the request is driven over the wire.
func TestIMAP_StatusRecent_ReflectsRecentMessages(t *testing.T) {
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
		t.Errorf("STATUS reported RECENT %d for a mailbox with %d never-SELECTed "+
			"messages; expected RECENT %d", recent, messages, messages)
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

// TestIMAP_StatusRecent_AfterExamineAndClose replays imaptest's "select" test
// (dovecot/imaptest src/tests/select, fixture select.mbox): STATUS (RECENT) must
// report what an EXAMINE of the mailbox reports (RFC 3501 §6.3.10 calls STATUS
// the alternative to an EXAMINE on a second connection). EXAMINE and CLOSE keep
// \Recent (§6.3.2); a read-write SELECT consumes it for later sessions
// (§2.3.2), and mail delivered after that is Recent again. LIST RETURN (STATUS)
// answers the same items (RFC 5819 §2).
func TestIMAP_StatusRecent_AfterExamineAndClose(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	conn, r := esearchDialLogin(t, server, account.Email, account.Password)
	defer conn.Close()
	const mbox = "test-mailbox"
	esearchCreate(t, conn, r, "c1", mbox)
	appendRaw := func(tag, msg string) {
		t.Helper()
		if _, err := fmt.Fprintf(conn, "%s APPEND %q {%d+}\r\n%s\r\n", tag, mbox, len(msg), msg); err != nil {
			t.Fatalf("APPEND write: %v", err)
		}
		if line := h3ReadTagged(t, r, tag); !strings.Contains(line, tag+" OK") {
			t.Fatalf("APPEND not OK:\n%s", line)
		}
	}
	appendRaw("a1", "Date: Sat, 24 Mar 2007 23:00:00 +0200\r\n\r\nbody\r\n")
	appendRaw("a2", "Date: Sat, 24 Mar 2007 23:00:00 +0200\r\n\r\nbody2\r\n")

	status := func(tag, items string) string {
		t.Helper()
		lines := esearchCmdOK(t, conn, r, tag, "STATUS "+esearchQuote(mbox)+" ("+items+")")
		return strings.Join(lines, "\n")
	}
	listStatusRecent := func(tag string) int {
		t.Helper()
		lines := esearchCmdOK(t, conn, r, tag, `LIST "" `+esearchQuote(mbox)+` RETURN (STATUS (RECENT))`)
		return h3ParseStatusItem(t, strings.Join(lines, "\n"), "RECENT")
	}

	// First open read-only so the Recent flags are not lost.
	lines, tagged := esearchExec(t, conn, r, "e1", "EXAMINE "+esearchQuote(mbox))
	if !strings.Contains(tagged, "OK [READ-ONLY]") || !slices.Contains(lines, "* 2 RECENT") {
		t.Fatalf("EXAMINE: want * 2 RECENT and OK [READ-ONLY], got %q / %q", lines, tagged)
	}
	esearchCmdOK(t, conn, r, "e2", "CLOSE")

	resp := status("s1", "MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN")
	for item, want := range map[string]int{"MESSAGES": 2, "RECENT": 2, "UIDNEXT": 3, "UNSEEN": 2} {
		if got := h3ParseStatusItem(t, resp, item); got != want {
			t.Errorf("STATUS after EXAMINE and CLOSE: %s %d, want %d (%s)", item, got, want, resp)
		}
	}
	if got := listStatusRecent("l1"); got != 2 {
		t.Errorf("LIST RETURN (STATUS (RECENT)) after EXAMINE and CLOSE: RECENT %d, want 2", got)
	}

	// Then read-write: SELECT still sees both, and consumes them.
	lines, tagged = esearchExec(t, conn, r, "w1", "SELECT "+esearchQuote(mbox))
	if !strings.Contains(tagged, "OK [READ-WRITE]") || !slices.Contains(lines, "* 2 RECENT") {
		t.Fatalf("SELECT: want * 2 RECENT and OK [READ-WRITE], got %q / %q", lines, tagged)
	}
	esearchCmdOK(t, conn, r, "w2", "CLOSE")
	if got := h3ParseStatusItem(t, status("s2", "RECENT"), "RECENT"); got != 0 {
		t.Errorf("STATUS after read-write SELECT: RECENT %d, want 0", got)
	}

	// A message delivered after that SELECT is Recent again.
	appendRaw("a3", "Date: Sat, 24 Mar 2007 23:00:00 +0200\r\n\r\nbody3\r\n")
	if got := h3ParseStatusItem(t, status("s3", "RECENT"), "RECENT"); got != 1 {
		t.Errorf("STATUS after a new delivery: RECENT %d, want 1", got)
	}
	if got := listStatusRecent("l2"); got != 1 {
		t.Errorf("LIST RETURN (STATUS (RECENT)) after a new delivery: RECENT %d, want 1", got)
	}
}

// TestIMAP_StatusRecent_SelectedMailboxMatchesSelect: STATUS of the selected
// mailbox (which RFC 3501 §6.3.10 discourages but allows) reports this
// session's \Recent messages, the count SELECT announced, while another
// connection, opening after the read-write SELECT, sees none.
func TestIMAP_StatusRecent_SelectedMailboxMatchesSelect(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	conn, r := esearchDialLogin(t, server, account.Email, account.Password)
	defer conn.Close()
	esearchCreate(t, conn, r, "c1", "Box")
	esearchAppend(t, conn, r, "a1", "Box", "one")
	esearchAppend(t, conn, r, "a2", "Box", "two")
	if lines := esearchCmdOK(t, conn, r, "w1", "SELECT Box"); !slices.Contains(lines, "* 2 RECENT") {
		t.Fatalf("SELECT: want * 2 RECENT, got %q", lines)
	}
	resp := strings.Join(esearchCmdOK(t, conn, r, "s1", "STATUS Box (RECENT)"), "\n")
	if got := h3ParseStatusItem(t, resp, "RECENT"); got != 2 {
		t.Errorf("STATUS of the selected mailbox: RECENT %d, want 2 as SELECT said", got)
	}

	other, r2 := esearchDialLogin(t, server, account.Email, account.Password)
	defer other.Close()
	resp = strings.Join(esearchCmdOK(t, other, r2, "s2", "STATUS Box (RECENT)"), "\n")
	if got := h3ParseStatusItem(t, resp, "RECENT"); got != 0 {
		t.Errorf("STATUS from another connection after the read-write SELECT: RECENT %d, want 0", got)
	}
}

// TestIMAP_MultiSearchRecentMatchesStatus: in a mailbox that is not selected,
// multimailbox SEARCH RECENT and OLD (RFC 7377, which sets no rule of its own
// for \Recent) answer from the same messages STATUS (RECENT) counts: those
// above the last read-write SELECT, all of them before the first one.
func TestIMAP_MultiSearchRecentMatchesStatus(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	conn, r := esearchDialLogin(t, server, account.Email, account.Password)
	defer conn.Close()
	esearchCreate(t, conn, r, "c1", "other")
	esearchAppend(t, conn, r, "a1", "other", "one")
	esearchAppend(t, conn, r, "a2", "other", "two")
	esearchCmdOK(t, conn, r, "c2", "SELECT INBOX")

	check := func(step string, wantRecent int, recentUIDs, oldUIDs string) {
		t.Helper()
		resp := strings.Join(esearchCmdOK(t, conn, r, "s"+step, "STATUS other (RECENT)"), "\n")
		if got := h3ParseStatusItem(t, resp, "RECENT"); got != wantRecent {
			t.Errorf("%s: STATUS other RECENT %d, want %d", step, got, wantRecent)
		}
		for _, tc := range []struct{ key, want string }{{"RECENT", recentUIDs}, {"OLD", oldUIDs}} {
			lines := esearchCmdOK(t, conn, r, "q"+step+tc.key, `ESEARCH IN (mailboxes "other") RETURN (ALL) `+tc.key)
			line := esearchLine(lines, "other")
			if tc.want == "" {
				if line != "" {
					t.Errorf("%s: ESEARCH IN (mailboxes other) %s: want no result, got %q", step, tc.key, line)
				}
			} else if !strings.HasSuffix(line, " ALL "+tc.want) {
				t.Errorf("%s: ESEARCH IN (mailboxes other) %s: want ALL %s, got %q", step, tc.key, tc.want, lines)
			}
		}
	}
	check("1", 2, "1:2", "")

	// Another connection selects it read-write: both are old now, and a later
	// delivery is the one recent message.
	other, r2 := esearchDialLogin(t, server, account.Email, account.Password)
	defer other.Close()
	esearchCmdOK(t, other, r2, "o1", "SELECT other")
	esearchCmdOK(t, other, r2, "o2", "CLOSE")
	esearchAppend(t, conn, r, "a3", "other", "three")
	check("2", 1, "3", "1:2")
}
