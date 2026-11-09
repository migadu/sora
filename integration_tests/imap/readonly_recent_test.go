//go:build integration

package imap_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// RFC 3501 §§2.3.2 and 6.3.2: read-only opens must leave \Recent available
// both to the current session's next open and to the next read-write session.
func TestIMAP_ExamineReselectPreservesRecent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	conn, r := esearchDialLogin(t, server, owner.Email, owner.Password)
	defer conn.Close()
	esearchAppend(t, conn, r, "a1", "INBOX", "recent")
	for i, command := range []string{"EXAMINE INBOX", "EXAMINE INBOX", "SELECT INBOX"} {
		lines := esearchCmdOK(t, conn, r, fmt.Sprintf("s%d", i), command)
		require.True(t, slices.Contains(lines, "* 1 RECENT"), "%s must retain RECENT: %q", command, lines)
		for j, tc := range []struct{ key, want string }{{"RECENT", "1"}, {"NEW", "1"}, {"OLD", ""}} {
			lines = esearchCmdOK(t, conn, r, fmt.Sprintf("q%d%d", i, j), "UID SEARCH "+tc.key)
			require.Equal(t, tc.want, responseNums(lines, "* SEARCH"), "%s after %s", tc.key, command)
		}
	}
	other, rr := esearchDialLogin(t, server, owner.Email, owner.Password)
	defer other.Close()
	lines := esearchCmdOK(t, other, rr, "z1", "SELECT INBOX")
	require.True(t, slices.Contains(lines, "* 0 RECENT"), "read-write SELECT must consume RECENT for subsequent sessions: %q", lines)
}

func TestIMAP_ReadOnlySharedOpensPreserveRecent(t *testing.T) {
	for _, tc := range []struct{ command, rights string }{{"SELECT", "lr"}, {"EXAMINE", "lrswipkxtea"}} {
		t.Run(tc.command, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()
			member, password := createSecondUser(t, server, "example.com", "recentreader")
			ownerConn, ownerR := esearchDialLogin(t, server, owner.Email, owner.Password)
			defer ownerConn.Close()
			esearchCreate(t, ownerConn, ownerR, "a1", "Shared/Notice")
			esearchCmdOK(t, ownerConn, ownerR, "a2", "SETACL Shared/Notice "+esearchQuote(member)+" "+tc.rights)
			esearchAppend(t, ownerConn, ownerR, "a3", "Shared/Notice", "notice")
			conn, r := esearchDialLogin(t, server, member, password)
			defer conn.Close()
			lines, tagged := esearchExec(t, conn, r, "s1", tc.command+" Shared/Notice")
			require.Contains(t, tagged, "OK [READ-ONLY]")
			require.True(t, slices.Contains(lines, "* 1 RECENT"), "read-only selection must retain RECENT: %q", lines)
			lines = esearchCmdOK(t, conn, r, "q1", "UID SEARCH RECENT")
			require.Equal(t, "1", responseNums(lines, "* SEARCH"))
			lines = esearchCmdOK(t, ownerConn, ownerR, "a4", "SELECT Shared/Notice")
			require.True(t, slices.Contains(lines, "* 1 RECENT"), "owner must still see RECENT after read-only opens: %q", lines)
			require.Equal(t, "1", responseNums(esearchCmdOK(t, ownerConn, ownerR, "a5", "UID SEARCH RECENT"), "* SEARCH"))
		})
	}
}

func TestIMAP_ExamineOtherMailboxDoesNotReviveConsumedRecent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	first, r1 := esearchDialLogin(t, server, owner.Email, owner.Password)
	defer first.Close()
	esearchAppend(t, first, r1, "a1", "INBOX", "old")
	esearchCmdOK(t, first, r1, "a2", "SELECT INBOX")
	esearchCreate(t, first, r1, "a3", "Other")
	esearchCmdOK(t, first, r1, "a4", "EXAMINE Other")
	// INBOX is now closed in the first session. A new read-write session is
	// the first to select it after this delivery and consumes the new Recent.
	second, r2 := esearchDialLogin(t, server, owner.Email, owner.Password)
	defer second.Close()
	esearchAppend(t, second, r2, "b1", "INBOX", "new")
	lines := esearchCmdOK(t, second, r2, "b2", "SELECT INBOX")
	require.Contains(t, lines, "* 1 RECENT")
	lines = esearchCmdOK(t, first, r1, "a5", "EXAMINE INBOX")
	require.Contains(t, lines, "* 0 RECENT", "an old session baseline cannot revive Recent consumed while INBOX was closed")
	require.Empty(t, responseNums(esearchCmdOK(t, first, r1, "a6", "UID SEARCH RECENT"), "* SEARCH"))
}
