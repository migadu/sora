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

var flagListRe = regexp.MustCompile(`FLAGS \(([^)]*)\)`)

// flagTokens returns the flags of the first "FLAGS (...)" list in line.
func flagTokens(line string) []string {
	m := flagListRe.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	return strings.Fields(m[1])
}

// TestIMAP_StoreNILKeyword is the keyword half of imaptest's "nil" scenario
// (#2013). NIL is an atom, and RFC 3501 §9 / RFC 9051 §9 define flag-keyword as
// an atom with no nil alternative in flag-list or store-att-flags, so
// "STORE 1 +FLAGS NIL" sets the keyword NIL. It must then round-trip like any
// other keyword: in the STORE echo, FETCH FLAGS, the mailbox FLAGS list,
// SEARCH KEYWORD and APPEND.
func TestIMAP_StoreNILKeyword(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	c.do("CREATE NilKeyword")
	msg := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: nil\r\n\r\nbody\r\n"
	c.appendMsg("NilKeyword", msg)
	c.do("SELECT NilKeyword")

	hasNIL := func(lines []string, prefix string) bool {
		for _, l := range lines {
			if strings.HasPrefix(l, prefix) && slices.Contains(flagTokens(l), "NIL") {
				return true
			}
		}
		return false
	}

	// The exchange from the issue: an unparenthesized flag argument.
	untagged, _ := c.do("STORE 1 +FLAGS NIL")
	if !hasNIL(untagged, "* 1 FETCH ") {
		t.Errorf("STORE 1 +FLAGS NIL: echo lacks keyword NIL: %q", untagged)
	}

	untagged, _ = c.do("FETCH 1 FLAGS")
	if !hasNIL(untagged, "* 1 FETCH ") {
		t.Errorf("FETCH 1 FLAGS after storing NIL lacks keyword NIL: %q", untagged)
	}

	untagged, _ = c.do("SEARCH KEYWORD NIL")
	if !slices.Contains(untagged, "* SEARCH 1") {
		t.Errorf("SEARCH KEYWORD NIL = %q, want * SEARCH 1", untagged)
	}

	// A fresh SELECT lists the keyword in use in the mailbox FLAGS.
	untagged, _ = c.do("SELECT NilKeyword")
	if !hasNIL(untagged, "* FLAGS ") {
		t.Errorf("SELECT FLAGS lacks keyword NIL in use: %q", untagged)
	}

	// The parenthesized form on APPEND stores it too.
	tag := c.nextTag()
	if _, err := fmt.Fprintf(c.conn, "%s APPEND NilKeyword (NIL) {%d+}\r\n%s\r\n", tag, len(msg), msg); err != nil {
		t.Fatalf("append write: %v", err)
	}
	c.collect(tag, "APPEND (NIL)")
	untagged, _ = c.do("FETCH 2 FLAGS")
	if !hasNIL(untagged, "* 2 FETCH ") {
		t.Errorf("APPEND (NIL): FETCH 2 FLAGS lacks keyword NIL: %q", untagged)
	}

	// Removing it works like any keyword.
	c.do("STORE 1 -FLAGS (NIL)")
	untagged, _ = c.do("FETCH 1 FLAGS")
	if hasNIL(untagged, "* 1 FETCH ") {
		t.Errorf("STORE 1 -FLAGS (NIL) left keyword NIL: %q", untagged)
	}
}
