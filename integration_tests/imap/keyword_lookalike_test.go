//go:build integration

package imap_test

import (
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// "ABNF strings are case insensitive and the character set for these strings
// is US-ASCII" (RFC 5234 §2.3). go-imap upper-cased client atoms with
// strings.ToUpper and compared them with strings.EqualFold, so U+017F (LATIN
// SMALL LETTER LONG S) was taken as "S" and U+0131 (LATIN SMALL LETTER DOTLESS
// I) as "I": the commands below were executed instead of refused (#1511).
func TestIMAP_KeywordLookalikesAreNotKeywords(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	const (
		longS    = "\u017f"
		dotlessI = "\u0131"
	)

	// Before authentication an unknown command is BAD and ends the connection.
	pre := dialRaw(t, server.Address)
	untagged, tagged := pre.cmd("p", "CAPAB"+dotlessI+"LITY")
	assert.True(t, strings.HasPrefix(tagged, "p BAD"), "CAPAB%sLITY: %s (untagged %q)", dotlessI, tagged, untagged)
	_ = pre.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	bye, err := pre.r.ReadString('\n')
	assert.NoError(t, err, "after CAPAB%sLITY", dotlessI)
	assert.True(t, strings.HasPrefix(bye, "* BYE"), "after CAPAB%sLITY: %q, want BYE", dotlessI, bye)
	_, err = pre.r.ReadString('\n')
	assert.Error(t, err, "connection still open after BYE")
	pre.conn.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)
	rc.append("P", "INBOX", "From: a@example.com\r\nSubject: sort\r\n\r\nbody\r\n")
	_, tagged = rc.cmd("S", "SELECT INBOX")
	require.True(t, strings.HasPrefix(tagged, "S OK"), "%s", tagged)

	for _, tc := range []struct{ command, want string }{
		{longS + "TATUS INBOX (MESSAGES)", "BAD"},
		{"STATUS INBOX (MESSAGE" + longS + ")", "BAD"},
		{"U" + dotlessI + "D SEARCH ALL", "BAD"},
		{"UID " + longS + "EARCH ALL", "BAD"},
		{"SEARCH " + longS + "UBJECT sort", "BAD"},
		{"SEARCH CHAR" + longS + "ET UTF-8 ALL", "BAD"},
		{"SEARCH CHARSET U" + longS + "-A" + longS + "C" + dotlessI + "I ALL", "NO [BADCHARSET]"},
		{"SEARCH RETURN (M" + dotlessI + "N) ALL", "BAD"},
		{"SORT (" + longS + "IZE) UTF-8 ALL", "BAD"},
		{"SORT (REVER" + longS + "E DATE) UTF-8 ALL", "BAD"},
		{"FETCH 1 (FLAG" + longS + ")", "BAD"},
		{"FETCH 1 BODY.PEEK[HEADER.F" + dotlessI + "ELDS (Subject)]", "BAD"},
		{longS + "ELECT INBOX", "BAD"},
	} {
		untagged, tagged := rc.cmd("A", tc.command)
		assert.True(t, strings.HasPrefix(tagged, "A "+tc.want), "%s: %s, want %s (untagged %q)", tc.command, tagged, tc.want, untagged)
		assert.Empty(t, untagged, "%s", tc.command)
		_, tagged = rc.cmd("N", "NOOP")
		require.True(t, strings.HasPrefix(tagged, "N OK"), "NOOP after %s: %s", tc.command, tagged)
	}

	// The same keywords in ASCII, in any case, are served.
	for _, tc := range []struct{ command, want string }{
		{"status INBOX (messages)", "* STATUS INBOX (MESSAGES 1)"},
		{"uid search subject sort", "* SEARCH "},
		{"search charset us-ascii all", "* SEARCH 1"},
		{"sort (reverse size) utf-8 all", "* SORT 1"},
	} {
		untagged, tagged := rc.cmd("G", tc.command)
		require.True(t, strings.HasPrefix(tagged, "G OK"), "%s: %s", tc.command, tagged)
		assert.Contains(t, strings.Join(untagged, "\n"), tc.want, "%s", tc.command)
	}
}
