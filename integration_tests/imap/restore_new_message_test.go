//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestIMAP_RestoredMessageIsNewToEverySession: a message brought back by
// `sora-admin messages restore` (or the Admin API) appears in its mailbox, and every
// client learns of it the way it learns of any new message. RFC 7162 §3.1: "When a
// message is appended to a mailbox (via the IMAP APPEND command, COPY to the mailbox,
// or using an external mechanism), the server generates a new modification sequence
// that is higher than the highest modification sequence of all messages in the
// mailbox and assigns it to the appended message." A QRESYNC client that last
// synchronized after the expunge must therefore see HIGHESTMODSEQ rise and be sent
// the restored message, a session that has the mailbox selected must be told of it on
// its next NOOP, and a NOTIFY session watching the mailbox must be sent its STATUS
// (RFC 5465 §5.2: MessageNew).
func TestIMAP_RestoredMessageIsNewToEverySession(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	t.Cleanup(server.Close)

	viewer := dialRaw(t, server.Address)
	t.Cleanup(func() { viewer.conn.Close() })
	viewer.login(account)
	setupInboxWith(t, viewer, 2) // UIDs 1 and 2, INBOX selected

	other := dialRaw(t, server.Address)
	t.Cleanup(func() { other.conn.Close() })
	other.login(account)
	_, tagged := other.cmd("o1", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	_, tagged = other.cmd("o2", `UID STORE 1 +FLAGS.SILENT (\Deleted)`)
	require.Contains(t, tagged, "OK")
	_, tagged = other.cmd("o3", "EXPUNGE")
	require.Contains(t, tagged, "OK")

	untagged, tagged := viewer.cmd("v1", "NOOP")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"1"}, expungeSeqs(untagged))

	// A QRESYNC client synchronizes after the expunge.
	resync := dialRaw(t, server.Address)
	t.Cleanup(func() { resync.conn.Close() })
	resync.login(account)
	_, tagged = resync.cmd("r1", "ENABLE QRESYNC")
	require.Contains(t, tagged, "OK")
	untagged, tagged = resync.cmd("r2", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	m := selectUIDValidityRe.FindStringSubmatch(fmt.Sprint(untagged))
	require.NotNil(t, m, "no UIDVALIDITY in %q", untagged)
	uidValidity := m[1]
	codes := highestModSeqCodes(t, untagged)
	require.Len(t, codes, 1)
	synced := codes[0]

	// A NOTIFY session watches INBOX without selecting it.
	watcher := dialRaw(t, server.Address)
	t.Cleanup(func() { watcher.conn.Close() })
	watcher.login(account)
	untagged, tagged = watcher.cmd("w1", "NOTIFY SET STATUS (personal (MessageNew MessageExpunge))")
	require.Contains(t, tagged, "OK")
	initial := statusLines(untagged, "INBOX")
	require.Len(t, initial, 1, "the initial STATUS of NOTIFY SET STATUS: %q", untagged)
	require.Contains(t, initial[0], "(MESSAGES 1 UIDNEXT 3 ")

	inbox := "INBOX"
	restored, err := server.ResilientDB.RestoreMessagesWithRetry(context.Background(),
		db.RestoreMessagesParams{Email: account.Email, MailboxPath: &inbox})
	require.NoError(t, err)
	require.Equal(t, int64(1), restored)

	// The restored message comes back as UID 3: a UID is never reused.
	untagged, tagged = viewer.cmd("v2", "NOOP")
	require.Contains(t, tagged, "OK")
	t.Logf("viewer NOOP after restore: %q", untagged)
	require.Contains(t, untagged, "* 2 EXISTS", "the selected session must be told of the restored message")
	untagged, tagged = viewer.cmd("v3", "FETCH 2 (UID)")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"2:3"}, seqUIDPairs(untagged))

	// The watcher's pump runs every notifyTestPollInterval; NOOP collects what it sent.
	var notified []string
	for deadline := time.Now().Add(5 * time.Second); len(notified) == 0 && time.Now().Before(deadline); {
		time.Sleep(notifyTestPollInterval)
		untagged, tagged = watcher.cmd("w2", "NOOP")
		require.Contains(t, tagged, "OK")
		notified = statusLines(untagged, "INBOX")
	}
	require.Len(t, notified, 1, "the NOTIFY session must be sent INBOX's new STATUS")
	require.Contains(t, notified[0], "(MESSAGES 2 UIDNEXT 4 ")

	untagged, tagged = resync.cmd("r3", fmt.Sprintf("SELECT INBOX (QRESYNC (%s %d))", uidValidity, synced))
	require.Contains(t, tagged, "OK")
	t.Logf("QRESYNC SELECT after restore: %q", untagged)
	codes = highestModSeqCodes(t, untagged)
	require.Len(t, codes, 1)
	highest := codes[0]
	require.Greater(t, highest, synced, "HIGHESTMODSEQ must rise when a message appears in the mailbox")
	require.Equal(t, []string{"2:3"}, seqUIDPairs(untagged), "QRESYNC must send the restored message")
	require.LessOrEqual(t, maxModSeqItem(t, untagged), highest)

	untagged, tagged = resync.cmd("r4", "UID FETCH 1:* (FLAGS) (CHANGEDSINCE "+strconv.FormatUint(synced, 10)+")")
	require.Contains(t, tagged, "OK")
	t.Logf("CHANGEDSINCE after restore: %q", untagged)
	require.Equal(t, []string{"2:3"}, seqUIDPairs(untagged), "CHANGEDSINCE must return the restored message")
	require.LessOrEqual(t, maxModSeqItem(t, untagged), highest,
		"no message's MODSEQ may exceed the mailbox's HIGHESTMODSEQ")
}

// statusLines returns the untagged STATUS responses for mailbox among untagged.
func statusLines(untagged []string, mailbox string) []string {
	var lines []string
	for _, l := range untagged {
		if strings.HasPrefix(l, "* STATUS "+mailbox+" (") || strings.HasPrefix(l, `* STATUS "`+mailbox+`" (`) {
			lines = append(lines, l)
		}
	}
	return lines
}
