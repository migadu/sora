//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
)

// A node with [shared_mailboxes] enabled = false serves no other owner's shared
// mailbox: LIST omits it and every command naming it answers as for a mailbox that
// does not exist, for a direct grant and an "anyone" grant alike. The owner keeps
// its shared mailboxes there, and a node with sharing on still serves them to the
// grantee, since the grants are untouched.
func TestIMAP_SharedMailboxesDisabledHidesOtherOwners(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	on, _ := common.SetupIMAPServer(t)
	defer on.Close()
	off, _ := common.SetupIMAPServerWithOptions(t, &common.IMAPServerOpts{SharedMailboxes: &config.SharedMailboxesConfig{
		Enabled: false, NamespacePrefix: "Shared/", AllowUserCreate: true, DefaultRights: "lrswipkxtea",
	}})
	defer off.Close()

	domain := common.UniqueTestDomain()
	owner := common.CreateTestAccountInDomain(t, on.ResilientDB, domain)
	grantee := common.CreateTestAccountInDomain(t, on.ResilientDB, domain)
	login := func(server *common.TestServer, account common.TestAccount) *rawIMAP {
		c := dialRawIMAP(t, server.Address)
		c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
		return c
	}

	o := login(on, owner)
	for _, box := range []string{"Shared/Direct", "Shared/Public"} {
		o.do("CREATE " + box)
		o.appendMsg(box, "From: owner@example.com\r\nSubject: shared\r\n\r\nbody\r\n")
	}
	o.do(fmt.Sprintf("SETACL Shared/Direct %s lrswipkxtea", grantee.Email))
	o.do("SETACL Shared/Public anyone lrswipkxtea")

	listed := func(c *rawIMAP) string {
		lines, _ := c.do(`LIST "" "*"`)
		return strings.Join(lines, "\n")
	}

	g := login(on, grantee)
	for _, box := range []string{"Shared/Direct", "Shared/Public"} {
		if !strings.Contains(listed(g), box) {
			t.Fatalf("sharing on: %s missing from the grantee's LIST:\n%s", box, listed(g))
		}
	}

	g = login(off, grantee)
	if l := listed(g); strings.Contains(l, "Shared/Direct") || strings.Contains(l, "Shared/Public") {
		t.Errorf("sharing off: the grantee's LIST shows another owner's shared mailbox:\n%s", l)
	}
	for _, box := range []string{"Shared/Direct", "Shared/Public"} {
		for _, cmd := range []string{
			"SELECT " + box,
			"EXAMINE " + box,
			"STATUS " + box + " (MESSAGES)",
			"MYRIGHTS " + box,
			"GETACL " + box,
			"DELETE " + box,
			"RENAME " + box + " Mine",
		} {
			if got := g.status(cmd); !strings.HasPrefix(got, "NO") {
				t.Errorf("sharing off: %s = %q, want NO", cmd, got)
			}
		}
		// APPEND into it is refused too (TRYCREATE: it does not exist for this user).
		tag := g.nextTag()
		msg := "Subject: x\r\n\r\nx\r\n"
		if _, err := fmt.Fprintf(g.conn, "%s APPEND %s {%d+}\r\n%s\r\n", tag, box, len(msg), msg); err != nil {
			t.Fatal(err)
		}
		if _, tagged := g.read(tag, "APPEND"); !strings.Contains(tagged, "NO [TRYCREATE]") {
			t.Errorf("sharing off: APPEND %s = %q, want NO [TRYCREATE]", box, tagged)
		}
	}

	o = login(off, owner)
	for _, box := range []string{"Shared/Direct", "Shared/Public"} {
		if !strings.Contains(listed(o), box) {
			t.Errorf("sharing off: %s missing from the owner's LIST:\n%s", box, listed(o))
		}
		if lines, _ := o.do("SELECT " + box); !strings.Contains(strings.Join(lines, " "), "1 EXISTS") {
			t.Errorf("sharing off: owner SELECT %s: %v", box, lines)
		}
	}

	// The grants were not touched: the node with sharing on still serves them.
	g = login(on, grantee)
	if lines, _ := g.do("SELECT Shared/Public"); !strings.Contains(strings.Join(lines, " "), "1 EXISTS") {
		t.Errorf("sharing on after the off node: grantee SELECT: %v", lines)
	}
}
