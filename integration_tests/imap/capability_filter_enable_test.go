//go:build integration

package imap_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	imapserver "github.com/migadu/sora/server/imap"
)

// enableFilter withdraws two extensions IMAP4rev2 includes (RFC 9051 Appendix
// E) and two it does not, from the client named "buggy".
func enableFilter(o *imapserver.IMAPServerOptions) {
	o.CapabilityFilters = []config.ClientCapabilityFilter{{
		ClientName:  "^buggy$",
		DisableCaps: []string{"UIDPLUS", "MOVE", "CONDSTORE", "SORT"},
	}}
}

// advertisedCaps returns the capability names of the untagged CAPABILITY
// response in resp.
func advertisedCaps(t *testing.T, resp string) []string {
	t.Helper()
	for _, line := range strings.Split(resp, "\r\n") {
		if rest, ok := strings.CutPrefix(line, "* CAPABILITY "); ok {
			return strings.Fields(rest)
		}
	}
	t.Fatalf("no CAPABILITY response in:\n%s", resp)
	return nil
}

// A client filter matched by an ID sent after ENABLE took the enabled
// extensions away: with IMAP4rev2 gone the session refused UID EXPUNGE and MOVE
// with BAD while go-imap went on answering SEARCH with ESEARCH (#905). RFC 9051
// §6.3.1: "Once enabled using ENABLE, each extension remains active until the
// IMAP connection is closed." Extensions that depend on a kept capability and
// were not disabled themselves (QRESYNC on CONDSTORE) stay offered, while what
// the client has not enabled (SORT and its extensions here) is still withdrawn.
func TestIMAP_ClientFilterAfterEnableKeepsEnabledExtensions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	c := dialDisabledCaps(t, enableFilter, false)
	c.appendMessage()
	c.appendMessage()
	c.appendMessage()
	c.mustOK("CREATE Moved")

	if resp := c.mustOK("ENABLE IMAP4rev2 CONDSTORE"); !strings.Contains(resp, "* ENABLED IMAP4rev2 CONDSTORE\r\n") {
		t.Fatalf("ENABLE IMAP4rev2 CONDSTORE: want both enabled, got:\n%s", resp)
	}
	c.mustOK(`ID ("name" "buggy")`)

	caps := advertisedCaps(t, c.mustOK("CAPABILITY"))
	for _, want := range []string{"IMAP4rev2", "CONDSTORE", "QRESYNC"} {
		if !slices.Contains(caps, want) {
			t.Errorf("CAPABILITY after ENABLE and ID lost %s: %v", want, caps)
		}
	}
	for _, gone := range []string{"SORT", "SORT=DISPLAY", "ESORT"} {
		if slices.Contains(caps, gone) {
			t.Errorf("CAPABILITY still offers %s, which the filter withdraws and the client did not enable: %v", gone, caps)
		}
	}

	c.mustOK("SELECT INBOX")
	// RFC 7162 §3.1: a CONDSTORE-aware client gets mod-sequences in every
	// later untagged FETCH response.
	if resp := c.mustOK(`STORE 1 +FLAGS (\Flagged)`); !strings.Contains(resp, "MODSEQ (") {
		t.Errorf("STORE after ENABLE CONDSTORE: untagged FETCH without MODSEQ:\n%s", resp)
	}
	c.mustOK(`STORE 1 +FLAGS.SILENT (\Deleted)`)
	c.mustOK("UID EXPUNGE 1:*")
	c.mustOK("MOVE 1 Moved")
	if resp := c.mustOK("SEARCH ALL"); !strings.Contains(resp, "* ESEARCH ") {
		t.Errorf("SEARCH after ENABLE IMAP4rev2: want ESEARCH, got:\n%s", resp)
	}
}

// A filter matched before ENABLE still withdraws the extensions in full: the
// client cannot enable them afterwards and their commands are refused.
func TestIMAP_ClientFilterBeforeEnableWithdrawsExtensions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	c := dialDisabledCaps(t, enableFilter, true)
	c.appendMessage()

	if resp := c.mustOK("ENABLE IMAP4rev2 CONDSTORE"); !strings.Contains(resp, "* ENABLED\r\n") {
		t.Fatalf("ENABLE after a filter withdrew IMAP4rev2 and CONDSTORE: want nothing enabled, got:\n%s", resp)
	}
	caps := advertisedCaps(t, c.mustOK("CAPABILITY"))
	for _, gone := range []string{"IMAP4rev2", "UIDPLUS", "MOVE", "CONDSTORE", "QRESYNC"} {
		if slices.Contains(caps, gone) {
			t.Errorf("CAPABILITY still offers %s: %v", gone, caps)
		}
	}

	// go-imap refuses the CONDSTORE parameter of a session that does not offer
	// CONDSTORE, so the client does not become CONDSTORE-aware and a later ID
	// matching the same filter does not hand CONDSTORE back either.
	c.wantBad("SELECT INBOX (CONDSTORE)")
	c.mustOK("SELECT INBOX")
	c.wantBad("UID EXPUNGE 1:*")
	c.wantBad("MOVE 1 INBOX")
	c.mustOK(`ID ("name" "buggy")`)
	if caps := advertisedCaps(t, c.mustOK("CAPABILITY")); slices.Contains(caps, "CONDSTORE") {
		t.Errorf("CAPABILITY after SELECT (CONDSTORE) and a second ID offers CONDSTORE again: %v", caps)
	}
}

// A server without IMAP4rev1 serves every connection IMAP4rev2 whether or not
// the client enabled it, so a filter cannot take IMAP4rev2, or the extensions
// it includes, away from a session there either: the session was left offering
// neither IMAP4rev1 nor IMAP4rev2.
func TestIMAP_ClientFilterOnRev2OnlyServerKeepsIMAP4rev2(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	c := dialDisabledCaps(t, func(o *imapserver.IMAPServerOptions) {
		enableFilter(o)
		o.DisabledCaps = []string{"IMAP4rev1"}
	}, true)
	c.appendMessage()
	c.mustOK("CREATE Moved")

	caps := advertisedCaps(t, c.mustOK("CAPABILITY"))
	if !slices.Contains(caps, "IMAP4rev2") {
		t.Errorf("CAPABILITY of a session on a server without IMAP4rev1 lost IMAP4rev2: %v", caps)
	}
	if slices.Contains(caps, "CONDSTORE") {
		t.Errorf("CAPABILITY still offers CONDSTORE, which the filter withdraws: %v", caps)
	}
	c.mustOK("SELECT INBOX")
	c.mustOK("MOVE 1 Moved")
}

// SELECT (CONDSTORE) is a CONDSTORE enabling command just as ENABLE CONDSTORE
// is, and RFC 7162 §3.1 makes the server "include mod-sequence data in all
// subsequent untagged FETCH responses (until the connection is closed)" after
// any of them. A filter matched by a later ID kept taking CONDSTORE, and with it
// MODSEQ, away from such a client. What the client has not enabled is still
// withdrawn.
func TestIMAP_ClientFilterAfterCondStoreEnablingCommandKeepsCondStore(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	c := dialDisabledCaps(t, enableFilter, false)
	c.appendMessage()

	if resp := c.mustOK("SELECT INBOX (CONDSTORE)"); !strings.Contains(resp, "[HIGHESTMODSEQ ") {
		t.Fatalf("SELECT INBOX (CONDSTORE): want HIGHESTMODSEQ, got:\n%s", resp)
	}
	c.mustOK(`ID ("name" "buggy")`)

	caps := advertisedCaps(t, c.mustOK("CAPABILITY"))
	for _, want := range []string{"CONDSTORE", "QRESYNC"} {
		if !slices.Contains(caps, want) {
			t.Errorf("CAPABILITY after SELECT (CONDSTORE) and ID lost %s: %v", want, caps)
		}
	}
	for _, gone := range []string{"IMAP4rev2", "UIDPLUS", "MOVE", "SORT", "SORT=DISPLAY", "ESORT"} {
		if slices.Contains(caps, gone) {
			t.Errorf("CAPABILITY still offers %s, which the filter withdraws and the client did not enable: %v", gone, caps)
		}
	}
	if resp := c.mustOK(`STORE 1 +FLAGS (\Flagged)`); !strings.Contains(resp, "MODSEQ (") {
		t.Errorf("STORE after SELECT (CONDSTORE): untagged FETCH without MODSEQ:\n%s", resp)
	}
	c.wantBad("UID EXPUNGE 1:*")
}
