//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"testing"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestIMAP_RestoreReportsTheOldUIDsExpunge: `sora-admin messages restore` (or the Admin
// API) brings an expunged message back under a new UID, and the old UID's expunge must
// still reach every client that has not been told of it (#1712). A session that has the
// mailbox selected renumbers on the EXPUNGE (RFC 9051 §7.5.1), and its UIDs must not
// change under it (RFC 9051 §2.3.1.1: "The unique identifier of a message MUST NOT
// change during the session"). A QRESYNC client that synchronized before the expunge
// is sent it as VANISHED (EARLIER) (RFC 7162 §3.2.5.1: the server sends the client
// the expunges "that have occurred in this mailbox since the provided modification
// sequence", and "If the client did not provide the list of UIDs, the server acts as
// if the client has specified "1:<maxuid>""), and so is a UID FETCH with CHANGEDSINCE
// and VANISHED (RFC 7162 §3.2.6).
func TestIMAP_RestoreReportsTheOldUIDsExpunge(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	t.Cleanup(server.Close)

	viewer := dialRaw(t, server.Address)
	t.Cleanup(func() { viewer.conn.Close() })
	viewer.login(account)
	setupInboxWith(t, viewer, 3) // UIDs 1, 2 and 3, INBOX selected

	// A QRESYNC client synchronizes before the expunge, and leaves the mailbox.
	resync := dialRaw(t, server.Address)
	t.Cleanup(func() { resync.conn.Close() })
	resync.login(account)
	_, tagged := resync.cmd("r1", "ENABLE QRESYNC")
	require.Contains(t, tagged, "OK")
	untagged, tagged := resync.cmd("r2", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	m := selectUIDValidityRe.FindStringSubmatch(fmt.Sprint(untagged))
	require.NotNil(t, m, "no UIDVALIDITY in %q", untagged)
	uidValidity := m[1]
	codes := highestModSeqCodes(t, untagged)
	require.Len(t, codes, 1)
	synced := codes[0]
	_, tagged = resync.cmd("r3", "UNSELECT")
	require.Contains(t, tagged, "OK")

	other := dialRaw(t, server.Address)
	t.Cleanup(func() { other.conn.Close() })
	other.login(account)
	_, tagged = other.cmd("o1", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	_, tagged = other.cmd("o2", `UID STORE 1 +FLAGS.SILENT (\Deleted)`)
	require.Contains(t, tagged, "OK")
	_, tagged = other.cmd("o3", "EXPUNGE")
	require.Contains(t, tagged, "OK")

	// The viewer has not polled since the expunge when the message comes back as UID 4.
	inbox := "INBOX"
	restored, err := server.ResilientDB.RestoreMessagesWithRetry(context.Background(),
		db.RestoreMessagesParams{Email: account.Email, MailboxPath: &inbox})
	require.NoError(t, err)
	require.Equal(t, int64(1), restored)

	untagged, tagged = viewer.cmd("v1", "NOOP")
	require.Contains(t, tagged, "OK")
	t.Logf("viewer NOOP after restore: %q", untagged)
	require.Equal(t, []string{"1"}, expungeSeqs(untagged), "the viewer must be told UID 1 was expunged")
	expungeAt := slices.Index(untagged, "* 1 EXPUNGE")
	existsAt := slices.Index(untagged, "* 3 EXISTS")
	require.GreaterOrEqual(t, existsAt, 0, "the viewer must be told of the restored message")
	require.Less(t, expungeAt, existsAt, "the EXPUNGE renumbers before the EXISTS counts")
	untagged, tagged = viewer.cmd("v2", "FETCH 1:* (UID)")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"1:2", "2:3", "3:4"}, seqUIDPairs(untagged))

	untagged, tagged = resync.cmd("r4", fmt.Sprintf("SELECT INBOX (QRESYNC (%s %d))", uidValidity, synced))
	require.Contains(t, tagged, "OK")
	t.Logf("QRESYNC SELECT after restore: %q", untagged)
	require.True(t, slices.Contains(untagged, "* VANISHED (EARLIER) 1"),
		"QRESYNC without known-uids must report UID 1 as vanished: %q", untagged)
	require.Equal(t, []string{"3:4"}, seqUIDPairs(untagged), "QRESYNC must send the restored message")

	untagged, tagged = resync.cmd("r5", "UID FETCH 1:* (FLAGS) (CHANGEDSINCE "+strconv.FormatUint(synced, 10)+" VANISHED)")
	require.Contains(t, tagged, "OK")
	t.Logf("UID FETCH CHANGEDSINCE VANISHED after restore: %q", untagged)
	require.True(t, slices.Contains(untagged, "* VANISHED (EARLIER) 1"),
		"UID FETCH (CHANGEDSINCE ... VANISHED) must report UID 1 as vanished: %q", untagged)
	require.Equal(t, []string{"3:4"}, seqUIDPairs(untagged))
}
