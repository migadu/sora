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
// that arrived since the last read-write SELECT, as the RECENT count does.
func TestIMAP_RecentIsSessionState(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Session A: UIDs 1 and 2, then a read-write SELECT that makes them old for
	// later sessions. A then asks for \Recent on UID 1, appends UID 3 with it
	// and UID 4 without, and fills another mailbox with UIDs 1-3 carrying it.
	connA, rA := esearchDialLogin(t, server, account.Email, account.Password)
	defer connA.Close()
	esearchAppend(t, connA, rA, "a1", "INBOX", "one")
	esearchAppend(t, connA, rA, "a2", "INBOX", "two")
	esearchCmdOK(t, connA, rA, "a3", "SELECT INBOX")
	esearchCmdOK(t, connA, rA, "a4", `UID STORE 1 +FLAGS (\Recent)`)
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

	for _, l := range esearchCmdOK(t, connB, rB, "b3", "FETCH 1:* FLAGS") {
		if strings.Contains(strings.ToLower(l), `\recent`) {
			t.Errorf("FETCH FLAGS reports a stored \\Recent: %q", l)
		}
	}

	// Multimailbox SEARCH: B has seen nothing arrive in Other, so nothing there
	// is recent, though its UIDs are above INBOX's threshold.
	recent := esearchCmdOK(t, connB, rB, "b4", `ESEARCH IN (personal) RETURN (ALL) RECENT`)
	if got := esearchMailboxes(t, recent); len(got) != 1 || !strings.HasSuffix(esearchLine(recent, "INBOX"), " ALL 3:4") {
		t.Errorf("ESEARCH IN (personal) RECENT: want only INBOX 3:4, got %q", recent)
	}
	old := esearchCmdOK(t, connB, rB, "b5", `ESEARCH IN (personal) RETURN (ALL) OLD`)
	if !strings.HasSuffix(esearchLine(old, "INBOX"), " ALL 1:2") || !strings.HasSuffix(esearchLine(old, "Other"), " ALL 1:3") {
		t.Errorf("ESEARCH IN (personal) OLD: want INBOX 1:2 and Other 1:3, got %q", old)
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
