//go:build integration

package imap_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_FetchVanishedRequiresEnableQResync: the VANISHED UID FETCH modifier
// is QRESYNC's, and advertising QRESYNC is not enough to use it. RFC 7162
// §3.2.6: "A server MUST respond with a tagged BAD response if the VANISHED UID
// FETCH modifier is specified and the client hasn't issued "ENABLE QRESYNC" in
// the current connection." It was served, with a VANISHED (EARLIER) response,
// whenever QRESYNC was advertised (#1054). Every form go-imap parses is covered:
// the RFC 4466 parenthesised list, the "(CHANGEDSINCE n) VANISHED" hybrid and
// the bare "CHANGEDSINCE n VANISHED". After ENABLE QRESYNC the same commands are
// served, VANISHED (EARLIER) first (RFC 7162 §3.2.6).
func TestIMAP_FetchVanishedRequiresEnableQResync(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	t.Cleanup(server.Close)

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
	capLines, _ := c.do("CAPABILITY")
	if caps := strings.Fields(strings.Join(capLines, " ")); !slices.Contains(caps, "QRESYNC") {
		t.Fatalf("CAPABILITY: want QRESYNC advertised, got:\n%s", strings.Join(capLines, "\n"))
	}
	msg := "From: a@example.com\r\nTo: b@example.com\r\nSubject: vanished\r\n\r\nhello\r\n"
	expunged := c.appendMsg("INBOX", msg)
	c.appendMsg("INBOX", msg)
	c.do("SELECT INBOX")
	c.do(`STORE 1 +FLAGS.SILENT (\Deleted)`)
	c.do("EXPUNGE")

	cmds := []string{
		"UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1 VANISHED)",
		"UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1) VANISHED",
		"UID FETCH 1:* (FLAGS) CHANGEDSINCE 1 VANISHED",
	}
	run := func(c *rawIMAP, cmd string) (untagged []string, status, resp string) {
		t.Helper()
		tag := c.send(cmd)
		untagged, tagged := c.read(tag, cmd)
		return untagged, strings.TrimPrefix(tagged, tag+" "), strings.Join(append(untagged, tagged), "\n")
	}

	for _, cmd := range cmds {
		untagged, status, resp := run(c, cmd)
		if !strings.HasPrefix(status, "BAD ") || len(untagged) > 0 {
			t.Errorf("%s without ENABLE QRESYNC: want BAD and no untagged response, got:\n%s", cmd, resp)
		}
	}
	// CHANGEDSINCE alone is CONDSTORE's and needs no ENABLE (RFC 7162 §3.1).
	if _, status, resp := run(c, "UID FETCH 1:* (FLAGS) (CHANGEDSINCE 1)"); !strings.HasPrefix(status, "OK ") {
		t.Errorf("UID FETCH CHANGEDSINCE without ENABLE QRESYNC: want OK, got:\n%s", resp)
	}

	// A second connection enables QRESYNC the way RFC 5161 §3.1 requires:
	// "Clients MUST NOT issue ENABLE once they SELECT/EXAMINE a mailbox", so
	// CLOSE on the first connection would not do.
	q := dialRawIMAP(t, server.Address)
	q.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
	if enabled, _ := q.do("ENABLE QRESYNC"); !slices.Contains(enabled, "* ENABLED QRESYNC") {
		t.Fatalf("ENABLE QRESYNC: want * ENABLED QRESYNC, got:\n%s", strings.Join(enabled, "\n"))
	}
	q.do("SELECT INBOX")

	wantVanished := fmt.Sprintf("* VANISHED (EARLIER) %d", expunged)
	for _, cmd := range cmds {
		untagged, status, resp := run(q, cmd)
		if !strings.HasPrefix(status, "OK ") || len(untagged) == 0 || untagged[0] != wantVanished {
			t.Errorf("%s after ENABLE QRESYNC: want OK with %q first, got:\n%s", cmd, wantVanished, resp)
		}
	}
}
