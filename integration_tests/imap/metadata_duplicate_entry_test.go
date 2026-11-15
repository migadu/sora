//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// RFC 5464 §3.2: "Entry names are case-insensitive." A SETMETADATA naming one
// entry twice in different letter case stored whichever of the two values Go's
// map iteration happened to visit last. It is now BAD, for server and mailbox
// metadata, and changes nothing: neither a new entry nor an existing value.
func TestIMAP_SetMetadataSameEntryInTwoCasesIsBAD(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)

	get := func(mailbox, entry string) []string {
		untagged, tagged := rc.cmd("G", fmt.Sprintf("GETMETADATA %s (%s)", mailbox, entry))
		require.True(t, strings.HasPrefix(tagged, "G OK"), "GETMETADATA %s %s: %s", mailbox, entry, tagged)
		return untagged
	}

	for _, mailbox := range []string{`""`, "INBOX"} {
		_, tagged := rc.cmd("S", fmt.Sprintf(`SETMETADATA %s (/private/keep "old")`, mailbox))
		require.True(t, strings.HasPrefix(tagged, "S OK"), "%s: %s", mailbox, tagged)

		for _, list := range []string{
			`/private/A "1" /private/a NIL`,
			`/private/a NIL /private/A "1"`,
			`/SHARED/new "1" /shared/NEW "2"`,
			`/private/Keep "new" /private/keep NIL`,
			`/private/other "1" /PRIVATE/KEEP "new" /private/keep "newer"`,
		} {
			command := fmt.Sprintf("SETMETADATA %s (%s)", mailbox, list)
			untagged, tagged := rc.cmd("A", command)
			require.True(t, strings.HasPrefix(tagged, "A BAD"), "%s: %s", command, tagged)
			require.Empty(t, untagged, "%s", command)
		}

		for _, entry := range []string{"/private/a", "/shared/new", "/private/other"} {
			require.Empty(t, get(mailbox, entry), "%s %s was stored", mailbox, entry)
		}
		require.Equal(t, []string{fmt.Sprintf(`* METADATA %s ("/private/keep" "old")`, mailbox)}, get(mailbox, "/private/keep"))
	}

	// Control: the same name spelled the same way twice never reaches the
	// session as two entries (go-imap keeps the later value as it parses), so
	// the command is accepted and the later occurrence wins.
	for _, step := range []struct{ list, want string }{
		{`/private/dup "1" /private/dup "2"`, `* METADATA "" ("/private/dup" "2")`},
		{`/private/dup "3" /private/dup NIL`, ""},
	} {
		_, tagged := rc.cmd("D", fmt.Sprintf(`SETMETADATA "" (%s)`, step.list))
		require.True(t, strings.HasPrefix(tagged, "D OK"), "%s: %s", step.list, tagged)
		untagged := get(`""`, "/private/dup")
		if step.want == "" {
			require.Empty(t, untagged, "%s", step.list)
		} else {
			require.Equal(t, []string{step.want}, untagged, "%s", step.list)
		}
	}
}
