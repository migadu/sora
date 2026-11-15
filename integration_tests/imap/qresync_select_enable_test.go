//go:build integration

package imap_test

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

var statusUIDValidityRe = regexp.MustCompile(`\(UIDVALIDITY (\d+)\)`)

// TestIMAP_SelectQResyncRequiresEnableQResync: the QRESYNC parameter to
// SELECT/EXAMINE needs ENABLE QRESYNC, and advertising QRESYNC is not enough.
// RFC 7162 §3.2.5: "A server MUST respond with a tagged BAD response if the
// Quick Resynchronization parameter to the SELECT/EXAMINE command is specified
// and the client hasn't issued "ENABLE QRESYNC" in the current connection".
// Without ENABLE the parameter's arguments were left unread: a bare "(QRESYNC)"
// was accepted and the mailbox selected, and a well-formed parameter was
// refused only by the syntax error on the argument list left behind (#1195).
// After ENABLE QRESYNC the well-formed commands are served and the bare
// parameter, which has no argument list (RFC 7162 §7), stays BAD.
func TestIMAP_SelectQResyncRequiresEnableQResync(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	t.Cleanup(server.Close)

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
	capLines, _ := c.do("CAPABILITY")
	if caps := strings.Fields(strings.Join(capLines, " ")); !slices.Contains(caps, "QRESYNC") {
		t.Fatalf("CAPABILITY: want QRESYNC advertised, got:\n%s", strings.Join(capLines, "\n"))
	}
	statusLines, _ := c.do("STATUS INBOX (UIDVALIDITY)")
	m := statusUIDValidityRe.FindStringSubmatch(strings.Join(statusLines, "\n"))
	if m == nil {
		t.Fatalf("STATUS INBOX (UIDVALIDITY): no UIDVALIDITY in:\n%s", strings.Join(statusLines, "\n"))
	}
	uidValidity := m[1]

	wellFormed := []string{
		fmt.Sprintf("SELECT INBOX (QRESYNC (%s 1))", uidValidity),
		fmt.Sprintf("EXAMINE INBOX (QRESYNC (%s 1 1:10))", uidValidity),
	}
	bare := []string{
		"SELECT INBOX (QRESYNC)",
		"SELECT INBOX (QRESYNC CONDSTORE)",
	}

	// A refused SELECT/EXAMINE must leave no mailbox selected: CLOSE is then
	// refused, where after a selection it would succeed.
	assertNotSelected := func(after string) {
		t.Helper()
		if status := c.status("CLOSE"); strings.HasPrefix(status, "OK") {
			t.Errorf("CLOSE after %s = %q: want it refused, no mailbox may be selected", after, status)
		}
	}

	for _, cmd := range append(slices.Clone(wellFormed), bare...) {
		if status := c.status(cmd); !strings.HasPrefix(status, "BAD ") || !strings.Contains(status, "ENABLE QRESYNC") {
			t.Errorf("%s without ENABLE QRESYNC = %q: want BAD naming ENABLE QRESYNC", cmd, status)
		}
		assertNotSelected(cmd)
	}

	if enabled, _ := c.do("ENABLE QRESYNC"); !slices.Contains(enabled, "* ENABLED QRESYNC") {
		t.Fatalf("ENABLE QRESYNC: want * ENABLED QRESYNC, got:\n%s", strings.Join(enabled, "\n"))
	}

	for _, cmd := range wellFormed {
		if status := c.status(cmd); !strings.HasPrefix(status, "OK ") {
			t.Errorf("%s after ENABLE QRESYNC = %q: want OK", cmd, status)
		}
		c.do("CLOSE")
	}
	for _, cmd := range bare {
		if status := c.status(cmd); !strings.HasPrefix(status, "BAD ") {
			t.Errorf("%s after ENABLE QRESYNC = %q: want BAD, the parameter has no argument list", cmd, status)
		}
		assertNotSelected(cmd)
	}
}
