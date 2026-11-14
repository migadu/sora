//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_SearchMalformedStringIsBad sends search strings PostgreSQL cannot
// take as text: a NUL, which no IMAP string may contain (RFC 9051 §9 rule 3),
// and bytes that are not UTF-8 (RFC 9051 §6.4.4), which go-imap also lets into
// a KEYWORD atom. Each is the client's error and gets BAD, never NO [SERVERBUG]
// with the database's error text (#594).
func TestIMAP_SearchMalformedStringIsBad(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialPreview(t, server.Address, account)
	c.appendMessage("From: alice@example.com\nTo: bob@example.com\nSubject: café\n\nCafé au lait.\n")
	if err := server.FlushFTSQueue(); err != nil {
		t.Fatalf("FlushFTSQueue: %v", err)
	}

	literal := func(s string) string { return fmt.Sprintf("{%d+}\r\n%s", len(s), s) }
	for _, command := range []string{
		"UID SEARCH HEADER Subject " + literal("\x00"),
		"UID SEARCH SUBJECT " + literal("a\x00"),
		"UID SEARCH FROM " + literal("\x00"),
		"UID SEARCH HEADER " + literal("\x00") + " value",
		"UID SEARCH HEADER " + literal("\xff") + " value",
		"UID SEARCH BODY " + literal("\xff"),
		"UID SEARCH TEXT " + literal("\xff"),
		"UID SEARCH SUBJECT " + literal("\xff"),
		"UID SEARCH NOT BODY " + literal("caf\xc3"),
		"UID SEARCH OR SUBJECT " + literal("\xff") + " ALL",
		"UID SEARCH BODY " + literal("\x00"),
		"UID SEARCH KEYWORD \xa9\xff",
		"UID SEARCH UNKEYWORD \xa9\xff",
		"UID SORT (ARRIVAL) UTF-8 BODY " + literal("\xff"),
		"UID THREAD REFERENCES UTF-8 BODY " + literal("\xff"),
		"ESEARCH IN (selected) RETURN (ALL) BODY " + literal("\xff"),
	} {
		_, tagged := c.run(command)
		if !strings.HasPrefix(tagged, "BAD ") {
			t.Errorf("%q = %q, want BAD", command, tagged)
		}
	}
	// A charset the server does not implement keeps its NO [BADCHARSET] response;
	// its byte encoding cannot be judged as UTF-8 by this validator.
	_, tagged := c.run("UID SEARCH CHARSET ISO-8859-1 BODY " + literal("\xff"))
	if !strings.HasPrefix(tagged, "NO [BADCHARSET]") {
		t.Errorf("unsupported charset = %q, want NO [BADCHARSET]", tagged)
	}

	// Well-formed UTF-8 is still searched, and the session survived the BADs.
	for _, command := range []string{
		"UID SEARCH CHARSET UTF-8 SUBJECT " + literal("café"),
		"UID SEARCH CHARSET UTF-8 BODY " + literal("café"),
		"UID SEARCH SUBJECT " + literal("café"),
	} {
		untagged, tagged := c.run(command)
		if !strings.HasPrefix(tagged, "OK") || !strings.Contains(untagged, "* SEARCH 1") {
			t.Errorf("%q = %q %q, want * SEARCH 1 and OK", command, untagged, tagged)
		}
	}
}
