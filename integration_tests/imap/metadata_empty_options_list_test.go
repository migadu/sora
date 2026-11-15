//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// RFC 5464 §5:
//
//	getmetadata       = "GETMETADATA" [SP getmetadata-options]
//	                                  SP mailbox SP entries
//	getmetadata-options = "(" getmetadata-option
//	                          *(SP getmetadata-option) ")"
//
// An options list holds at least one option and is followed by SP; §4.2 answers
// "BAD - command unknown or arguments invalid". An empty list was taken as no
// options and the SP after it was no longer required: "GETMETADATA ()INBOX ..."
// was answered OK, and "GETMETADATA () INBOX ..." BAD only for the SP, with
// "expected ASTRING-CHAR".
func TestIMAP_MetadataEmptyOptionsListIsBAD(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)

	_, tagged := rc.cmd("S", `SETMETADATA INBOX (/private/comment "x")`)
	require.True(t, strings.HasPrefix(tagged, "S OK"), "%s", tagged)

	for _, command := range []string{
		`GETMETADATA ()INBOX (/private/comment)`,
		`GETMETADATA () INBOX (/private/comment)`,
		`GETMETADATA ()"" (/private/comment)`,
		`GETMETADATA () "" /private/comment`,
	} {
		untagged, tagged := rc.cmd("A", command)
		require.True(t, strings.HasPrefix(tagged, "A BAD"), "%s: %s", command, tagged)
		require.Contains(t, strings.ToLower(tagged), "option", "%s: the BAD should name the empty options list", command)
		require.Empty(t, untagged, "%s", command)
	}

	// The SP after a non-empty options list was already required.
	untagged, tagged := rc.cmd("B", `GETMETADATA (DEPTH 0)INBOX (/private/comment)`)
	require.True(t, strings.HasPrefix(tagged, "B BAD"), "%s", tagged)
	require.Empty(t, untagged)

	// Control: a one-option list and no list are both accepted.
	for _, command := range []string{
		`GETMETADATA (DEPTH 0) INBOX (/private/comment)`,
		`GETMETADATA INBOX (/private/comment)`,
	} {
		untagged, tagged := rc.cmd("G", command)
		require.True(t, strings.HasPrefix(tagged, "G OK"), "%s: %s", command, tagged)
		require.Equal(t, []string{`* METADATA INBOX ("/private/comment" "x")`}, untagged, "%s", command)
	}
}
