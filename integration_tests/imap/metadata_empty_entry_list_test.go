//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// RFC 5464 §5: "entries = entry / "(" entry *(SP entry) ")"" and
// "entry-values = "(" entry-value *(SP entry-value) ")"". An empty entry list
// is malformed, and §4.2 and §4.3 answer "BAD - command unknown or arguments
// invalid". Both commands were answered OK. The grammar is checked before the
// mailbox is looked up, so a mailbox that does not exist is BAD too, not NO.
func TestIMAP_MetadataEmptyEntryListIsBAD(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)

	for _, mailbox := range []string{`""`, "INBOX", "NoSuchMailbox"} {
		for _, command := range []string{
			fmt.Sprintf("SETMETADATA %s ()", mailbox),
			fmt.Sprintf("GETMETADATA %s ()", mailbox),
			fmt.Sprintf("GETMETADATA (DEPTH infinity) %s ()", mailbox),
		} {
			untagged, tagged := rc.cmd("A", command)
			require.True(t, strings.HasPrefix(tagged, "A BAD"), "%s: %s", command, tagged)
			require.Empty(t, untagged, "%s", command)
		}
	}

	// Control: a one-entry list is accepted.
	_, tagged := rc.cmd("S", `SETMETADATA INBOX (/private/comment "x")`)
	require.True(t, strings.HasPrefix(tagged, "S OK"), "%s", tagged)
	untagged, tagged := rc.cmd("G", "GETMETADATA INBOX (/private/comment)")
	require.True(t, strings.HasPrefix(tagged, "G OK"), "%s", tagged)
	require.Equal(t, []string{`* METADATA INBOX ("/private/comment" "x")`}, untagged)
}
