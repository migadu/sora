//go:build integration

package imap_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_RecentIsSessionState: \Recent sent in STORE or APPEND is not stored
// (RFC 3501 §2.3.2: it "can not be altered by the client"), and SEARCH, SORT,
// THREAD and multimailbox SEARCH answer RECENT, NEW and OLD with the messages
// that arrived since the last read-write SELECT, as the RECENT count does. The
// FLAGS of every FETCH response (FETCH, STORE, QRESYNC and unsolicited) carry
// \Recent for exactly those messages in an IMAP4rev1 session (RFC 3501 §7.3.2:
// "The only reliable way to identify recent messages is to look at message
// flags to see which have the \Recent flag set, or to do a SEARCH RECENT"),
// and never in an IMAP4rev2 one (RFC 9051 Appendix E item 12).
func TestIMAP_RecentIsSessionState(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Session A: UIDs 1 and 2, then a read-write SELECT that makes them old for
	// later sessions. A then asks for \Recent on UID 1, closes INBOX, appends
	// UID 3 with it and UID 4 without, and fills another mailbox with UIDs 1-3 carrying it.
	connA, rA := esearchDialLogin(t, server, account.Email, account.Password)
	defer connA.Close()
	esearchAppend(t, connA, rA, "a1", "INBOX", "one")
	esearchAppend(t, connA, rA, "a2", "INBOX", "two")
	esearchCmdOK(t, connA, rA, "a3", "SELECT INBOX")
	esearchCmdOK(t, connA, rA, "a4", `UID STORE 1 +FLAGS (\Recent)`)
	// A closes INBOX: a read-write session that has it selected would be notified
	// of the appends below and consume their \Recent before B selects.
	esearchCmdOK(t, connA, rA, "a4c", "CLOSE")
	recentAppend(t, connA, rA, "a5", "INBOX", "three")
	esearchAppend(t, connA, rA, "a6", "INBOX", "four")
	esearchCreate(t, connA, rA, "a7", "Other")
	for i := range 3 {
		recentAppend(t, connA, rA, fmt.Sprintf("a8%d", i), "Other", "other")
	}

	ctx := context.Background()
	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account ID: %v", err)
	}
	var stored int
	if err := server.ResilientDB.QueryRowWithRetry(ctx, `
		SELECT count(*) FROM messages m
		JOIN message_state ms ON ms.message_id = m.id AND ms.mailbox_id = m.mailbox_id
		WHERE m.account_id = $1 AND (ms.flags & 32) != 0
	`, accountID).Scan(&stored); err != nil {
		t.Fatalf("count stored \\Recent: %v", err)
	}
	if stored != 0 {
		t.Errorf("%d messages have the \\Recent bit stored, want 0", stored)
	}

	// INBOX has no expunged messages, so a message's number is its UID below.
	// EXAMINE leaves \Recent to the next read-write SELECT (RFC 3501 §6.3.2),
	// so UIDs 3 and 4 are \Recent in each of these sessions and still in B's.
	connQ, rQ := esearchDialLogin(t, server, account.Email, account.Password)
	defer connQ.Close()
	esearchCmdOK(t, connQ, rQ, "q1", "ENABLE QRESYNC")
	var uidValidity uint32
	for _, l := range esearchCmdOK(t, connQ, rQ, "q2", "STATUS INBOX (UIDVALIDITY)") {
		fmt.Sscanf(l, "* STATUS INBOX (UIDVALIDITY %d)", &uidValidity)
	}
	if uidValidity == 0 {
		t.Fatal("STATUS INBOX returned no UIDVALIDITY")
	}
	qresync := esearchCmdOK(t, connQ, rQ, "q3", fmt.Sprintf("EXAMINE INBOX (QRESYNC (%d 1))", uidValidity))
	assertFetchRecent(t, "EXAMINE INBOX (QRESYNC)", qresync, []int{3, 4}, []int{3, 4})

	connR2, rR2 := esearchDialLogin(t, server, account.Email, account.Password)
	defer connR2.Close()
	esearchCmdOK(t, connR2, rR2, "r1", "ENABLE IMAP4rev2")
	esearchCmdOK(t, connR2, rR2, "r2", "EXAMINE INBOX")
	assertFetchRecent(t, "IMAP4rev2 FETCH 1:* FLAGS", esearchCmdOK(t, connR2, rR2, "r3", "FETCH 1:* FLAGS"), []int{1, 2, 3, 4}, nil)

	// Session B: UIDs 3 and 4 arrived since A's SELECT.
	connB, rB := esearchDialLogin(t, server, account.Email, account.Password)
	defer connB.Close()
	if lines := esearchCmdOK(t, connB, rB, "b1", "SELECT INBOX"); !slices.Contains(lines, "* 2 RECENT") {
		t.Fatalf("SELECT INBOX: want * 2 RECENT, got %q", lines)
	}

	for i, tc := range []struct{ cmd, prefix, want string }{
		{"UID SEARCH RECENT", "* SEARCH", "3 4"},
		{"UID SEARCH NEW", "* SEARCH", "3 4"},
		{"UID SEARCH OLD", "* SEARCH", "1 2"},
		{"UID SEARCH OR RECENT UID 1", "* SEARCH", "1 3 4"},
		{"UID SORT (ARRIVAL) UTF-8 RECENT", "* SORT", "3 4"},
		{"UID THREAD ORDEREDSUBJECT UTF-8 RECENT", "* THREAD", "(3)(4)"},
	} {
		lines := esearchCmdOK(t, connB, rB, fmt.Sprintf("b2%d", i), tc.cmd)
		if got := responseNums(lines, tc.prefix); got != tc.want {
			t.Errorf("%s = %q, want %q", tc.cmd, got, tc.want)
		}
	}

	assertFetchRecent(t, "FETCH 1:* FLAGS", esearchCmdOK(t, connB, rB, "b3", "FETCH 1:* FLAGS"), []int{1, 2, 3, 4}, []int{3, 4})
	// STORE returns the new flags "as if a FETCH of those flags was done"
	// (RFC 3501 §6.4.6).
	assertFetchRecent(t, "UID STORE 1,3 +FLAGS", esearchCmdOK(t, connB, rB, "b3s", `UID STORE 1,3 +FLAGS (\Flagged)`), []int{1, 3}, []int{3})

	// Multimailbox SEARCH: INBOX answers from B's own threshold; Other, which no
	// session has selected read-write, from what an EXAMINE would see (as
	// STATUS does): all of it.
	recent := esearchCmdOK(t, connB, rB, "b4", `ESEARCH IN (personal) RETURN (ALL) RECENT`)
	if got := esearchMailboxes(t, recent); len(got) != 2 || !strings.HasSuffix(esearchLine(recent, "INBOX"), " ALL 3:4") || !strings.HasSuffix(esearchLine(recent, "Other"), " ALL 1:3") {
		t.Errorf("ESEARCH IN (personal) RECENT: want INBOX 3:4 and Other 1:3, got %q", recent)
	}
	old := esearchCmdOK(t, connB, rB, "b5", `ESEARCH IN (personal) RETURN (ALL) OLD`)
	if got := esearchMailboxes(t, old); len(got) != 1 || !strings.HasSuffix(esearchLine(old, "INBOX"), " ALL 1:2") {
		t.Errorf("ESEARCH IN (personal) OLD: want only INBOX 1:2, got %q", old)
	}

	// A selects INBOX after B: nothing is \Recent for A. A's flag changes reach
	// B as unsolicited FETCH responses, with B's \Recent.
	esearchCmdOK(t, connA, rA, "a9", "SELECT INBOX")
	assertFetchRecent(t, "A: UID STORE 2,4 +FLAGS", esearchCmdOK(t, connA, rA, "a10", `UID STORE 2,4 +FLAGS (\Seen)`), []int{2, 4}, nil)
	assertFetchRecent(t, "B: NOOP after A's STORE", esearchCmdOK(t, connB, rB, "b6", "NOOP"), []int{2, 4}, []int{4})
}

// assertFetchRecent checks that lines hold a FETCH response with FLAGS for each
// message number in fetched, and that \Recent is in the FLAGS of exactly the
// messages in recent.
func assertFetchRecent(t *testing.T, what string, lines []string, fetched, recent []int) {
	t.Helper()
	var gotFetched, gotRecent []int
	for _, l := range lines {
		var n int
		if _, err := fmt.Sscanf(l, "* %d FETCH", &n); err != nil || !strings.Contains(l, "FLAGS (") {
			continue
		}
		gotFetched = append(gotFetched, n)
		if strings.Contains(strings.ToLower(l), `\recent`) {
			gotRecent = append(gotRecent, n)
		}
	}
	slices.Sort(gotRecent)
	missing := slices.ContainsFunc(fetched, func(n int) bool { return !slices.Contains(gotFetched, n) })
	if missing || !slices.Equal(gotRecent, recent) {
		t.Errorf("%s: FLAGS for %v, \\Recent on %v; want FLAGS for %v, \\Recent on %v; responses %q",
			what, gotFetched, gotRecent, fetched, recent, lines)
	}
}

// recentAppend appends a message with the \Recent flag to mbox.
func recentAppend(t *testing.T, conn net.Conn, r *bufio.Reader, tag, mbox, subject string) {
	t.Helper()
	msg := "Subject: " + subject + "\r\n\r\nbody\r\n"
	_, tagged := esearchExecLiteral(t, conn, r, tag,
		fmt.Sprintf(`APPEND %s (\Recent) {%d+}`, esearchQuote(mbox), len(msg)), msg)
	if !strings.HasPrefix(tagged, tag+" OK") {
		t.Fatalf("APPEND %s (\\Recent): %q", mbox, tagged)
	}
}

// esearchExecLiteral is esearchExec for a command ending in a non-synchronizing
// literal, sent right after it.
func esearchExecLiteral(t *testing.T, conn net.Conn, r *bufio.Reader, tag, cmd, literal string) ([]string, string) {
	t.Helper()
	return esearchExec(t, conn, r, tag, cmd+"\r\n"+literal)
}

// responseNums returns the numbers of the untagged response starting with
// prefix, sorted, or for THREAD the thread list as sent.
func responseNums(lines []string, prefix string) string {
	for _, l := range lines {
		rest, ok := strings.CutPrefix(l, prefix)
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		if prefix == "* THREAD" {
			return rest
		}
		var nums []int
		for _, f := range strings.Fields(rest) {
			if n, err := strconv.Atoi(f); err == nil {
				nums = append(nums, n)
			}
		}
		slices.Sort(nums)
		return strings.Trim(fmt.Sprint(nums), "[]")
	}
	return ""
}

// esearchLine returns the multimailbox ESEARCH line for mailbox name.
func esearchLine(lines []string, name string) string {
	for _, l := range lines {
		if strings.Contains(l, " MAILBOX "+name+" ") || strings.Contains(l, " MAILBOX "+esearchQuote(name)+" ") {
			return l
		}
	}
	return ""
}
