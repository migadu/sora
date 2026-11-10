//go:build integration

package imap_test

import (
	"bufio"
	"net"
	"slices"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// RFC 3501 §2.3.2: once a read-write session has been notified of a message,
// "subsequent sessions will not see \Recent set for this message". That covers
// messages the session learns of while the mailbox is selected, not only those
// present when it was selected.

// recentNotifyTwo selects INBOX read-write while it is empty, appends two
// messages and has the session notified of them.
func recentNotifyTwo(t *testing.T, conn net.Conn, r *bufio.Reader) {
	t.Helper()
	lines := esearchCmdOK(t, conn, r, "n1", "SELECT INBOX")
	require.Contains(t, lines, "* 0 EXISTS")
	esearchAppend(t, conn, r, "n2", "INBOX", "one")
	esearchAppend(t, conn, r, "n3", "INBOX", "two")
	esearchCmdOK(t, conn, r, "n4", "NOOP")
	require.Equal(t, "1 2", responseNums(esearchCmdOK(t, conn, r, "n5", "UID SEARCH RECENT"), "* SEARCH"),
		"the notified read-write session sees the new messages as Recent")
}

func TestIMAP_RecentConsumedByNotifiedReadWriteSession_SameConnectionExamine(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	conn, r := esearchDialLogin(t, server, owner.Email, owner.Password)
	defer conn.Close()
	recentNotifyTwo(t, conn, r)

	lines := esearchCmdOK(t, conn, r, "e1", "EXAMINE INBOX")
	require.Contains(t, lines, "* 2 EXISTS")
	require.True(t, slices.Contains(lines, "* 0 RECENT"), "EXAMINE must not report Recent a second time: %q", lines)
	require.Empty(t, responseNums(esearchCmdOK(t, conn, r, "e2", "UID SEARCH RECENT"), "* SEARCH"))
	require.Equal(t, "1 2", responseNums(esearchCmdOK(t, conn, r, "e3", "UID SEARCH OLD"), "* SEARCH"))
}

func TestIMAP_RecentConsumedByNotifiedReadWriteSession_SecondConnection(t *testing.T) {
	for _, command := range []string{"SELECT", "EXAMINE"} {
		t.Run(command, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()
			first, r1 := esearchDialLogin(t, server, owner.Email, owner.Password)
			defer first.Close()
			recentNotifyTwo(t, first, r1)

			second, r2 := esearchDialLogin(t, server, owner.Email, owner.Password)
			defer second.Close()
			lines := esearchCmdOK(t, second, r2, "s1", command+" INBOX")
			require.Contains(t, lines, "* 2 EXISTS")
			require.True(t, slices.Contains(lines, "* 0 RECENT"), "%s must not report Recent a second time: %q", command, lines)
			require.Empty(t, responseNums(esearchCmdOK(t, second, r2, "s2", "UID SEARCH RECENT"), "* SEARCH"))

			// They stay Recent in the session that was notified of them.
			require.Equal(t, "1 2", responseNums(esearchCmdOK(t, first, r1, "f1", "UID SEARCH RECENT"), "* SEARCH"))
		})
	}
}

// The message is delivered by another connection into a mailbox whose baseline
// the read-write SELECT had already set.
func TestIMAP_RecentConsumedByNotifiedReadWriteSession_DeliveredElsewhere(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	first, r1 := esearchDialLogin(t, server, owner.Email, owner.Password)
	defer first.Close()
	esearchAppend(t, first, r1, "a1", "INBOX", "old")
	esearchCmdOK(t, first, r1, "a2", "SELECT INBOX")

	second, r2 := esearchDialLogin(t, server, owner.Email, owner.Password)
	defer second.Close()
	esearchAppend(t, second, r2, "b1", "INBOX", "new")

	lines := esearchCmdOK(t, first, r1, "a3", "NOOP")
	require.Contains(t, lines, "* 2 EXISTS")
	// Nothing had selected INBOX before, so both are Recent in the first session.
	require.Equal(t, "1 2", responseNums(esearchCmdOK(t, first, r1, "a4", "UID SEARCH RECENT"), "* SEARCH"))

	lines = esearchCmdOK(t, second, r2, "b2", "EXAMINE INBOX")
	require.True(t, slices.Contains(lines, "* 0 RECENT"), "EXAMINE must not report Recent a second time: %q", lines)
	lines = esearchCmdOK(t, second, r2, "b3", "SELECT INBOX")
	require.True(t, slices.Contains(lines, "* 0 RECENT"), "SELECT must not report Recent a second time: %q", lines)
	require.Empty(t, responseNums(esearchCmdOK(t, second, r2, "b4", "UID SEARCH RECENT"), "* SEARCH"))
}

// A read-only session that is notified of a message does not consume its
// Recent (RFC 3501 §6.3.2).
func TestIMAP_RecentNotConsumedByNotifiedReadOnlySession(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	first, r1 := esearchDialLogin(t, server, owner.Email, owner.Password)
	defer first.Close()
	esearchCmdOK(t, first, r1, "a1", "EXAMINE INBOX")

	second, r2 := esearchDialLogin(t, server, owner.Email, owner.Password)
	defer second.Close()
	esearchAppend(t, second, r2, "b1", "INBOX", "new")

	lines := esearchCmdOK(t, first, r1, "a2", "NOOP")
	require.Contains(t, lines, "* 1 EXISTS")

	lines = esearchCmdOK(t, second, r2, "b2", "SELECT INBOX")
	require.True(t, slices.Contains(lines, "* 1 RECENT"), "a read-only session must leave Recent for the next read-write one: %q", lines)
	require.Equal(t, "1", responseNums(esearchCmdOK(t, second, r2, "b3", "UID SEARCH RECENT"), "* SEARCH"))
}
