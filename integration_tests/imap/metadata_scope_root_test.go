//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// RFC 5464 §3.2: an entry name "MUST NOT end with a "/" character" and has at
// least two components; "Invalid entry names result in a BAD response in any
// IMAP command in which they are used". The scope roots /private and /shared,
// with or without the trailing slash, are therefore BAD in SETMETADATA and
// GETMETADATA (any depth), for server and mailbox metadata, and nothing is
// stored under them.
func TestIMAP_MetadataScopeRootIsBAD(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	rc := dialRaw(t, server.Address)
	defer rc.conn.Close()
	rc.login(account)

	// Control: a valid entry name is accepted, so the BADs below are about the
	// names and not about METADATA being unavailable.
	_, tagged := rc.cmd("V", `SETMETADATA "" (/private/comment "x")`)
	require.True(t, strings.HasPrefix(tagged, "V OK"), "valid entry: %s", tagged)

	for _, mailbox := range []string{`""`, "INBOX"} {
		for _, name := range []string{"/private/", "/shared/", "/PRIVATE/", "/private", "/shared"} {
			for _, command := range []string{
				fmt.Sprintf(`SETMETADATA %s (%s "x")`, mailbox, name),
				fmt.Sprintf(`GETMETADATA %s (%s)`, mailbox, name),
				fmt.Sprintf(`GETMETADATA (DEPTH infinity) %s (%s)`, mailbox, name),
			} {
				untagged, tagged := rc.cmd("A", command)
				require.True(t, strings.HasPrefix(tagged, "A BAD"), "%s: %s", command, tagged)
				require.Empty(t, untagged, "%s", command)
			}
		}
	}

	// A control character is invalid in an entry name too (RFC 5464 §3.2); a
	// literal carries it past the string syntax to the entry-name check.
	_, tagged = rc.cmd("C", "SETMETADATA \"\" ({10+}\r\n/private/\x01 \"x\")")
	require.True(t, strings.HasPrefix(tagged, "C BAD"), "control character: %s", tagged)

	ctx := context.Background()
	accountID, err := server.ResilientDB.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	inbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)
	for _, mailboxID := range []*int64{nil, &inbox.ID} {
		stored, err := server.ResilientDB.GetMetadataWithRetry(ctx, accountID, mailboxID,
			[]string{"/private/", "/shared/", "/private", "/shared", "/private/\x01"}, nil)
		require.NoError(t, err)
		require.Empty(t, stored.Entries, "mailboxID=%v", mailboxID)
	}
}
