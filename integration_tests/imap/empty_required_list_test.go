//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Where the grammar writes a list as "(" x *(SP x) ")", the list holds at least
// one element (RFC 9051 §9 fetch, header-list, status and search-key; RFC 5256
// §5 sort-criteria; RFC 5819 §4 status-option), and an empty "()" is "BAD -
// command unknown or arguments invalid" (RFC 9051 §6.4.5, §6.3.11). Each was
// answered OK: "FETCH 1 ()" with "* 1 FETCH ()", which msg-att does not allow,
// and "FETCH 1 BODY.PEEK[HEADER.FIELDS ()]" with the whole header as
// BODY[HEADER].
func TestIMAP_EmptyRequiredListIsBAD(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)
	rc.append("P", "INBOX", "From: a@example.com\r\nSubject: empty lists\r\n\r\nbody\r\n")
	_, tagged := rc.cmd("S", "SELECT INBOX")
	require.True(t, strings.HasPrefix(tagged, "S OK"), "%s", tagged)

	for _, command := range []string{
		`FETCH 1 ()`,
		`UID FETCH 1 ()`,
		`FETCH 1 BODY.PEEK[HEADER.FIELDS ()]`,
		`FETCH 1 BODY.PEEK[HEADER.FIELDS.NOT ()]`,
		`STATUS INBOX ()`,
		`SORT () UTF-8 ALL`,
		`SORT (DATE) UTF-8 ()`,
		`SEARCH ()`,
		`SEARCH NOT ()`,
		`SEARCH OR () ALL`,
		`UID SEARCH ()`,
		`THREAD REFERENCES UTF-8 ()`,
		`LIST "" "*" RETURN (STATUS ())`,
	} {
		untagged, tagged := rc.cmd("A", command)
		assert.True(t, strings.HasPrefix(tagged, "A BAD"), "%s: %s (untagged %q)", command, tagged, untagged)
		assert.Empty(t, untagged, "%s", command)
	}

	// The same lists with an element are served, and the lists the grammar lets
	// be empty stay accepted: the flag-list of STORE and APPEND (RFC 9051 §9),
	// LIST select and return options (RFC 5258 §6) and SEARCH RETURN () (RFC
	// 4731 §3.1). The message is \Recent in this session, the first to select
	// INBOX (RFC 3501 §2.3.2), which STORE's FLAGS keep.
	for _, tc := range []struct{ command, want string }{
		{`FETCH 1 (FLAGS)`, "* 1 FETCH (FLAGS ("},
		{`FETCH 1 BODY.PEEK[HEADER.FIELDS (Subject)]`, `* 1 FETCH (BODY[HEADER.FIELDS ("Subject")] {24}`},
		{`STATUS INBOX (MESSAGES)`, "* STATUS INBOX (MESSAGES 1)"},
		{`SORT (DATE) UTF-8 ALL`, "* SORT 1"},
		{`SEARCH NOT (DELETED)`, "* SEARCH 1"},
		{`THREAD REFERENCES UTF-8 (ALL)`, "* THREAD (1)"},
		{`LIST "" "*" RETURN (STATUS (MESSAGES))`, "* STATUS INBOX (MESSAGES 1)"},
		{`STORE 1 FLAGS (\Flagged)`, "* 1 FETCH (FLAGS (\\Flagged \\Recent)"},
		{`STORE 1 FLAGS ()`, "* 1 FETCH (FLAGS (\\Recent)"},
		{`LIST () "" "INBOX"`, "* LIST ("},
		{`LIST "" "INBOX" RETURN ()`, "* LIST ("},
		{`SEARCH RETURN () ALL`, "* ESEARCH "},
	} {
		untagged, tagged := rc.cmd("G", tc.command)
		require.True(t, strings.HasPrefix(tagged, "G OK"), "%s: %s", tc.command, tagged)
		require.Contains(t, strings.Join(untagged, "\n"), tc.want, "%s", tc.command)
	}
	untagged, tagged := rc.cmd("G", "APPEND INBOX () {5+}\r\nhello")
	require.True(t, strings.HasPrefix(tagged, "G OK"), "APPEND INBOX (): %s (untagged %q)", tagged, untagged)
}
