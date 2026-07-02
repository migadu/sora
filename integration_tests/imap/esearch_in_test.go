//go:build integration

package imap_test

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// These tests drive the RFC 7377 ESEARCH command (the "IN (source-options)"
// multimailbox SEARCH) over raw TCP, because the extended grammar and the exact
// wire shape of the response correlator are the point of the feature.
//
// RFC 7377 §2.1: every ESEARCH response carries the correlator
//
//	* ESEARCH (TAG "t" MAILBOX "<name>" UIDVALIDITY <n>) UID ALL <set>
//
// with MAILBOX and UIDVALIDITY *inside* the same parentheses as TAG, and results
// are always reported in UIDs.

// esearchLineRe matches an RFC 7377-shaped multimailbox ESEARCH response line.
// The mailbox name may be a quoted string or (for INBOX) a bare atom.
var esearchLineRe = regexp.MustCompile(`^\* ESEARCH \(TAG "[^"]+" MAILBOX (?:"([^"]*)"|([^ )]+)) UIDVALIDITY (\d+)\) UID `)

func esearchDialLogin(t *testing.T, server *common.TestServer, email, password string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("tcp", server.Address)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := bufio.NewReader(conn)
	if _, err := r.ReadString('\n'); err != nil { // greeting
		t.Fatalf("read greeting: %v", err)
	}
	esearchCmdOK(t, conn, r, "aL", fmt.Sprintf("LOGIN %q %q", email, password))
	return conn, r
}

// esearchExec sends a tagged command and reads until the tagged completion line,
// returning the untagged lines and the final tagged line.
func esearchExec(t *testing.T, conn net.Conn, r *bufio.Reader, tag, cmd string) (untagged []string, tagged string) {
	t.Helper()
	if _, err := fmt.Fprintf(conn, "%s %s\r\n", tag, cmd); err != nil {
		t.Fatalf("write %q: %v", cmd, err)
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("read after %q: %v", cmd, err)
		}
		line = strings.TrimRight(line, "\r\n")
		t.Logf("S: %s", line)
		if strings.HasPrefix(line, tag+" ") {
			return untagged, line
		}
		untagged = append(untagged, line)
	}
}

func esearchCmdOK(t *testing.T, conn net.Conn, r *bufio.Reader, tag, cmd string) []string {
	t.Helper()
	untagged, tagged := esearchExec(t, conn, r, tag, cmd)
	if !strings.HasPrefix(tagged, tag+" OK") {
		t.Fatalf("%s: expected OK, got %q", cmd, tagged)
	}
	return untagged
}

func esearchQuote(name string) string { return `"` + name + `"` }

func esearchCreate(t *testing.T, conn net.Conn, r *bufio.Reader, tag, mbox string) {
	t.Helper()
	_, tagged := esearchExec(t, conn, r, tag, "CREATE "+esearchQuote(mbox))
	if !strings.HasPrefix(tagged, tag+" OK") && !strings.Contains(tagged, "ALREADYEXISTS") {
		t.Fatalf("CREATE %s: %q", mbox, tagged)
	}
}

func esearchAppend(t *testing.T, conn net.Conn, r *bufio.Reader, tag, mbox, subject string) {
	t.Helper()
	msg := "Subject: " + subject + "\r\n\r\nbody\r\n"
	if _, err := fmt.Fprintf(conn, "%s APPEND %s {%d+}\r\n%s\r\n", tag, esearchQuote(mbox), len(msg), msg); err != nil {
		t.Fatalf("APPEND %s write: %v", mbox, err)
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("APPEND %s read: %v", mbox, err)
		}
		if strings.HasPrefix(line, tag+" ") {
			if !strings.HasPrefix(line, tag+" OK") {
				t.Fatalf("APPEND %s: %q", mbox, strings.TrimRight(line, "\r\n"))
			}
			return
		}
	}
}

// esearchMailboxes parses the untagged ESEARCH lines into a name→uidvalidity map,
// asserting each line has the RFC 7377 correlator shape.
func esearchMailboxes(t *testing.T, lines []string) map[string]string {
	t.Helper()
	res := map[string]string{}
	for _, l := range lines {
		if !strings.HasPrefix(l, "* ESEARCH") {
			continue
		}
		m := esearchLineRe.FindStringSubmatch(l)
		if m == nil {
			t.Errorf("ESEARCH line not RFC 7377-shaped "+
				"(want `(TAG .. MAILBOX .. UIDVALIDITY ..) UID ..`): %q", l)
			continue
		}
		name := m[1]
		if name == "" {
			name = m[2]
		}
		res[name] = m[3]
	}
	return res
}

func esearchAssertHas(t *testing.T, got map[string]string, want ...string) {
	t.Helper()
	for _, w := range want {
		if _, ok := got[w]; !ok {
			t.Errorf("expected ESEARCH result for %q; got mailboxes %v", w, got)
		}
	}
}

func TestIMAP_ESearchIn_Scopes(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	conn, r := esearchDialLogin(t, server, account.Email, account.Password)
	defer conn.Close()

	// A hierarchy under Work plus the default Archive mailbox.
	esearchCreate(t, conn, r, "c1", "Archive")
	esearchCreate(t, conn, r, "c2", "Work")
	esearchCreate(t, conn, r, "c3", "Work/2024")
	esearchCreate(t, conn, r, "c4", "Work/2024/Q1")

	// A matching message in each mailbox we will search (empty mailboxes are
	// suppressed per RFC 7377 §2.1).
	for i, mbox := range []string{"INBOX", "Archive", "Work", "Work/2024", "Work/2024/Q1"} {
		esearchAppend(t, conn, r, fmt.Sprintf("ap%d", i), mbox, "findme")
	}

	t.Run("Mailboxes", func(t *testing.T) {
		got := esearchMailboxes(t, esearchCmdOK(t, conn, r, "m1",
			`ESEARCH IN (mailboxes (INBOX Archive)) RETURN (ALL) SUBJECT "findme"`))
		esearchAssertHas(t, got, "INBOX", "Archive")
		if len(got) != 2 {
			t.Errorf("mailboxes: want exactly INBOX+Archive, got %v", got)
		}
	})

	t.Run("Subtree", func(t *testing.T) {
		got := esearchMailboxes(t, esearchCmdOK(t, conn, r, "s1",
			`ESEARCH IN (subtree "Work") RETURN (ALL) SUBJECT "findme"`))
		esearchAssertHas(t, got, "Work", "Work/2024", "Work/2024/Q1")
	})

	t.Run("SubtreeOne", func(t *testing.T) {
		got := esearchMailboxes(t, esearchCmdOK(t, conn, r, "so1",
			`ESEARCH IN (subtree-one "Work") RETURN (ALL) SUBJECT "findme"`))
		esearchAssertHas(t, got, "Work", "Work/2024")
		if _, ok := got["Work/2024/Q1"]; ok {
			t.Errorf("subtree-one must not include grandchild Work/2024/Q1: %v", got)
		}
	})

	t.Run("Personal", func(t *testing.T) {
		got := esearchMailboxes(t, esearchCmdOK(t, conn, r, "p1",
			`ESEARCH IN (personal) RETURN (ALL) SUBJECT "findme"`))
		esearchAssertHas(t, got, "INBOX", "Archive", "Work", "Work/2024", "Work/2024/Q1")
		if len(got) != 5 {
			t.Errorf("personal: want exactly the 5 mailboxes holding a match, got %v", got)
		}
	})

	t.Run("Subscribed", func(t *testing.T) {
		esearchCmdOK(t, conn, r, "sub1", `SUBSCRIBE "Work/2024"`)
		got := esearchMailboxes(t, esearchCmdOK(t, conn, r, "sb1",
			`ESEARCH IN (subscribed) RETURN (ALL) SUBJECT "findme"`))
		if _, ok := got["Work/2024"]; !ok {
			t.Errorf("subscribed must include the explicitly-subscribed Work/2024: %v", got)
		}
		if _, ok := got["Work"]; ok {
			t.Errorf("subscribed must NOT include the unsubscribed Work: %v", got)
		}
	})

	t.Run("NoIN_SelectedMailbox", func(t *testing.T) {
		esearchCmdOK(t, conn, r, "sel1", "SELECT INBOX")
		// No IN ⇒ "selected" assumed; the response still carries the
		// MAILBOX/UIDVALIDITY correlator (RFC 7377 §2.1).
		got := esearchMailboxes(t, esearchCmdOK(t, conn, r, "n1",
			`ESEARCH RETURN (ALL) SUBJECT "findme"`))
		esearchAssertHas(t, got, "INBOX")
	})

	t.Run("PlainSearchHasNoMailbox", func(t *testing.T) {
		// The RFC 4731 extended SEARCH command (not ESEARCH) on the selected
		// mailbox must NOT carry a MAILBOX correlator — regression guard.
		for _, l := range esearchCmdOK(t, conn, r, "ps1", `SEARCH RETURN (ALL) SUBJECT "findme"`) {
			if strings.HasPrefix(l, "* ESEARCH") && strings.Contains(l, "MAILBOX") {
				t.Errorf("plain SEARCH RETURN must not include MAILBOX: %q", l)
			}
		}
	})
}

// TestIMAP_ESearchIn_ACLExcludesUnreadable verifies that a mailbox the user can
// see (lookup 'l') but not read ('r') is silently excluded from ESEARCH results,
// so ESEARCH cannot leak UIDs/counts across an ACL boundary.
func TestIMAP_ESearchIn_ACLExcludesUnreadable(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	domain := strings.Split(owner.Email, "@")[1]
	granteeEmail := fmt.Sprintf("grantee-%d@%s", common.GetTimestamp(), domain)
	granteePass := "granteepass"
	if _, err := server.ResilientDB.CreateAccountWithRetry(context.Background(), db.CreateAccountRequest{
		Email:     granteeEmail,
		Password:  granteePass,
		HashType:  "bcrypt",
		IsPrimary: true,
	}); err != nil {
		t.Fatalf("create grantee: %v", err)
	}

	// Owner creates a shared mailbox and files a matching message in it.
	oconn, or := esearchDialLogin(t, server, owner.Email, owner.Password)
	defer oconn.Close()
	shared := fmt.Sprintf("Shared/ESearchACL-%d", common.GetTimestamp())
	esearchCmdOK(t, oconn, or, "sc", "CREATE "+esearchQuote(shared))
	esearchAppend(t, oconn, or, "sa", shared, "aclfind")

	ownerID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(context.Background(), owner.Email)
	if err != nil {
		t.Fatalf("owner account id: %v", err)
	}

	gconn, gr := esearchDialLogin(t, server, granteeEmail, granteePass)
	defer gconn.Close()

	cmd := fmt.Sprintf(`ESEARCH IN (mailboxes (%s)) RETURN (ALL) SUBJECT "aclfind"`, esearchQuote(shared))

	// Lookup-only: the mailbox is visible but must be excluded from ESEARCH.
	if err := server.ResilientDB.GrantMailboxAccessByIdentifierWithRetry(context.Background(), ownerID, granteeEmail, shared, "l"); err != nil {
		t.Fatalf("grant 'l': %v", err)
	}
	if got := esearchMailboxes(t, esearchCmdOK(t, gconn, gr, "g1", cmd)); len(got) != 0 {
		t.Errorf("grantee with only 'l' must get no ESEARCH result, got %v", got)
	}

	// Grant read: now the mailbox is included.
	if err := server.ResilientDB.GrantMailboxAccessByIdentifierWithRetry(context.Background(), ownerID, granteeEmail, shared, "lr"); err != nil {
		t.Fatalf("grant 'lr': %v", err)
	}
	if got := esearchMailboxes(t, esearchCmdOK(t, gconn, gr, "g2", cmd)); len(got) == 0 {
		t.Errorf("grantee with 'r' must get an ESEARCH result for %q, got none", shared)
	}
}
