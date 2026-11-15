//go:build integration

package imap_test

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// Sequence numbers belong to the session: RFC 9051 §7.5.1 renumbers a client's
// messages when the client is sent the EXPUNGE, "and this decrement is reflected in
// message sequence numbers in subsequent responses", and forbids sending it while
// responding to FETCH, STORE or SEARCH. Until then the client still numbers the
// messages as it was told, and a sequence number in a command, or in a response,
// must mean the message the client means, not its position in the mailbox as
// another session's EXPUNGE has already left it.
//
// Every test below starts from the same state: INBOX holds UIDs 1, 2 and 3, the
// viewer has it selected, and another session has expunged UID 1. The viewer has not
// been told, so its messages 1, 2 and 3 are still UIDs 1, 2 and 3.

// twoSessions returns a viewer with INBOX selected, holding UIDs 1..n, and a second
// session of the same account.
func twoSessions(t *testing.T, n int) (viewer, other *rawConn) {
	t.Helper()
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	t.Cleanup(server.Close)

	viewer = dialRaw(t, server.Address)
	t.Cleanup(func() { viewer.conn.Close() })
	viewer.login(account)
	setupInboxWith(t, viewer, n)

	other = dialRaw(t, server.Address)
	t.Cleanup(func() { other.conn.Close() })
	other.login(account)
	return viewer, other
}

// foreignExpungeSetup returns the viewer in the state described above.
func foreignExpungeSetup(t *testing.T) *rawConn {
	t.Helper()
	viewer, other := twoSessions(t, 3)
	// The destination of the COPY and MOVE tests, made here: any command of the
	// viewer that may send an EXPUNGE would end the state under test.
	_, tagged := other.cmd("o0", "CREATE Dest")
	require.Contains(t, tagged, "OK")
	_, tagged = other.cmd("o1", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	_, tagged = other.cmd("o2", `UID STORE 1 +FLAGS.SILENT (\Deleted)`)
	require.Contains(t, tagged, "OK")
	_, tagged = other.cmd("o3", "EXPUNGE")
	require.Contains(t, tagged, "OK")
	return viewer
}

var fetchLineRE = regexp.MustCompile(`^\* (\d+) FETCH \((.*)\)$`)
var uidItemRE = regexp.MustCompile(`\bUID (\d+)`)

// seqUIDPairs returns "seq:uid" for every untagged FETCH response carrying a UID.
func seqUIDPairs(untagged []string) []string {
	var pairs []string
	for _, l := range untagged {
		m := fetchLineRE.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if u := uidItemRE.FindStringSubmatch(m[2]); u != nil {
			pairs = append(pairs, m[1]+":"+u[1])
		}
	}
	return pairs
}

// flagsOfUID reads one message's flags through a fresh UID FETCH.
func flagsOfUID(t *testing.T, rc *rawConn, uid string) string {
	t.Helper()
	untagged, tagged := rc.cmd("fl"+uid, "UID FETCH "+uid+" (FLAGS)")
	require.Contains(t, tagged, "OK")
	for _, l := range untagged {
		if uidItemRE.FindStringSubmatch(l) != nil && strings.Contains(l, "UID "+uid) {
			return l
		}
	}
	t.Fatalf("no FETCH response for UID %s in %v", uid, untagged)
	return ""
}

// TestIMAP_SessionSeqNums_StoreAfterForeignExpunge is the report's reproduction: a
// sequence-number STORE flagged the client's message 3, and said so as message 2.
func TestIMAP_SessionSeqNums_StoreAfterForeignExpunge(t *testing.T) {
	viewer := foreignExpungeSetup(t)

	untagged, tagged := viewer.cmd("a2", `STORE 2 +FLAGS (\Flagged)`)
	require.Contains(t, tagged, "OK")
	t.Logf("STORE untagged: %v", untagged)
	require.Equal(t, []string{"2:2"}, seqUIDPairs(untagged),
		"STORE 2 must change the client's message 2 (UID 2) and report it as message 2")

	untagged, tagged = viewer.cmd("a3", "NOOP")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"1"}, expungeSeqs(untagged))

	require.Contains(t, flagsOfUID(t, viewer, "2"), `\Flagged`, "UID 2 is the message the client named")
	require.NotContains(t, flagsOfUID(t, viewer, "3"), `\Flagged`, "UID 3 was not named")
}

// TestIMAP_SessionSeqNums_StoreDeletedExpungeAfterForeignExpunge: the destructive
// form of the same bug, where STORE n +FLAGS (\Deleted) followed by EXPUNGE deletes
// a message the client did not name.
func TestIMAP_SessionSeqNums_StoreDeletedExpungeAfterForeignExpunge(t *testing.T) {
	viewer := foreignExpungeSetup(t)

	_, tagged := viewer.cmd("d1", `STORE 2 +FLAGS.SILENT (\Deleted)`)
	require.Contains(t, tagged, "OK")
	untagged, tagged := viewer.cmd("d2", "EXPUNGE")
	require.Contains(t, tagged, "OK")
	t.Logf("EXPUNGE untagged: %v", untagged)
	// UID 1 (message 1) and then UID 2 (message 1 once the first is gone).
	require.Equal(t, []string{"1", "1"}, expungeSeqs(untagged))

	untagged, tagged = viewer.cmd("d3", "UID FETCH 1:* (UID)")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"1:3"}, seqUIDPairs(untagged),
		"only UID 3 may remain: the client deleted its message 2, which is UID 2")
}

// TestIMAP_SessionSeqNums_FetchAfterForeignExpunge covers FETCH by sequence number,
// "*", and the sequence numbers of UID FETCH responses.
func TestIMAP_SessionSeqNums_FetchAfterForeignExpunge(t *testing.T) {
	viewer := foreignExpungeSetup(t)

	untagged, tagged := viewer.cmd("f1", "FETCH 2:3 (UID)")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"2:2", "3:3"}, seqUIDPairs(untagged))

	untagged, tagged = viewer.cmd("f2", "FETCH * (UID)")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"3:3"}, seqUIDPairs(untagged), `"*" is the client's last message`)

	untagged, tagged = viewer.cmd("f3", "UID FETCH 2:3 (FLAGS)")
	require.Contains(t, tagged, "OK")
	pairs := seqUIDPairs(untagged)
	// A UID command may deliver the EXPUNGE (RFC 9051 §7.5.1 Note); the FETCH
	// responses are numbered before it either way.
	require.Equal(t, []string{"2:2", "3:3"}, pairs, "UID FETCH responses must carry the client's sequence numbers")
}

// TestIMAP_SessionSeqNums_FetchWhileExpungeWithheld: once a poll has found the
// expunge, a FETCH's post-command poll still may not send it, so the client keeps
// the old numbering across several commands.
func TestIMAP_SessionSeqNums_FetchWhileExpungeWithheld(t *testing.T) {
	viewer := foreignExpungeSetup(t)

	for i, tag := range []string{"w1", "w2"} {
		untagged, tagged := viewer.cmd(tag, "FETCH 2:* (UID)")
		require.Contains(t, tagged, "OK")
		require.Empty(t, expungeSeqs(untagged), "no EXPUNGE during FETCH")
		require.Equal(t, []string{"2:2", "3:3"}, seqUIDPairs(untagged), "FETCH #%d", i+1)
	}

	untagged, tagged := viewer.cmd("w3", "NOOP")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"1"}, expungeSeqs(untagged))

	untagged, tagged = viewer.cmd("w4", "FETCH 1:* (UID)")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"1:2", "2:3"}, seqUIDPairs(untagged), "after the EXPUNGE the client renumbers")
}

// TestIMAP_SessionSeqNums_SearchAfterForeignExpunge: SEARCH results and
// sequence-set keys are in the client's numbering, so a STORE by the numbers a
// SEARCH returned lands on the messages it matched.
func TestIMAP_SessionSeqNums_SearchAfterForeignExpunge(t *testing.T) {
	viewer := foreignExpungeSetup(t)

	untagged, tagged := viewer.cmd("s1", "SEARCH UID 3")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"* SEARCH 3"}, untagged)

	untagged, tagged = viewer.cmd("s2", "SEARCH ALL")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"* SEARCH 2 3"}, untagged, "the live messages are the client's 2 and 3")

	untagged, tagged = viewer.cmd("s3", "SEARCH 3")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"* SEARCH 3"}, untagged, "sequence-set key 3 is the client's message 3")

	untagged, tagged = viewer.cmd("s3a", "SEARCH 1")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"* SEARCH"}, untagged, "the client's message 1 is gone")

	untagged, tagged = viewer.cmd("s3b", "SEARCH NOT 1")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"* SEARCH 2 3"}, untagged)

	// UID SEARCH may send the EXPUNGE, after its results.
	untagged, tagged = viewer.cmd("s4", "UID SEARCH 2")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"* SEARCH 2", "* 1 EXPUNGE"}, untagged, "the client's message 2 is UID 2")
}

// TestIMAP_SessionSeqNums_SortAfterForeignExpunge: SORT results are sequence
// numbers like SEARCH results.
func TestIMAP_SessionSeqNums_SortAfterForeignExpunge(t *testing.T) {
	viewer := foreignExpungeSetup(t)

	untagged, tagged := viewer.cmd("so1", "SORT (ARRIVAL) UTF-8 ALL")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"* SORT 2 3"}, untagged)
}

// copyUIDRE matches a COPYUID response code; group 1 is the source UID set.
var copyUIDRE = regexp.MustCompile(`\[COPYUID \d+ (\S+) (\S+)\]`)

// TestIMAP_SessionSeqNums_CopyAfterForeignExpunge: COPY by sequence number copies
// the client's message.
func TestIMAP_SessionSeqNums_CopyAfterForeignExpunge(t *testing.T) {
	viewer := foreignExpungeSetup(t)

	untagged, tagged := viewer.cmd("c1", "COPY 2 Dest")
	require.Contains(t, tagged, "OK")
	m := copyUIDRE.FindStringSubmatch(tagged)
	require.NotNil(t, m, "COPYUID expected in %q", tagged)
	require.Equal(t, "2", m[1], "COPY 2 must copy the client's message 2 (UID 2)")
	// COPY may send the EXPUNGE, after which the client numbers UID 2 as 1.
	require.Equal(t, []string{"1"}, expungeSeqs(untagged))

	_, tagged = viewer.cmd("c2", "COPY 1 Dest")
	require.Contains(t, tagged, "OK")
	m = copyUIDRE.FindStringSubmatch(tagged)
	require.NotNil(t, m, "COPYUID expected in %q", tagged)
	require.Equal(t, "2", m[1], "after the EXPUNGE, the client's message 1 is UID 2")
}

// TestIMAP_SessionSeqNums_MoveAfterForeignExpunge: MOVE by sequence number moves the
// client's message, and its EXPUNGE responses are in the client's numbering.
func TestIMAP_SessionSeqNums_MoveAfterForeignExpunge(t *testing.T) {
	viewer := foreignExpungeSetup(t)

	untagged, tagged := viewer.cmd("m1", "MOVE 2 Dest")
	require.Contains(t, tagged, "OK")
	t.Logf("MOVE untagged: %v", untagged)
	var src string
	for _, l := range untagged {
		if mm := copyUIDRE.FindStringSubmatch(l); mm != nil {
			src = mm[1]
		}
	}
	require.Equal(t, "2", src, "MOVE 2 must move the client's message 2 (UID 2)")
	// UID 2 (message 2), then UID 1 (message 1).
	require.Equal(t, []string{"2", "1"}, expungeSeqs(untagged))

	untagged, tagged = viewer.cmd("m2", "UID FETCH 1:* (UID)")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"1:3"}, seqUIDPairs(untagged))
}

// TestIMAP_SessionSeqNums_UnannouncedMessageHasNoNumber: a message whose EXISTS is
// held back behind a withheld EXPUNGE is not one of the client's messages yet, so
// "*" does not reach it and no response numbers it.
func TestIMAP_SessionSeqNums_UnannouncedMessageHasNoNumber(t *testing.T) {
	viewer, other := twoSessions(t, 3)
	other.append("o1", "INBOX", msg(4)) // UID 4
	_, tagged := other.cmd("o2", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	_, tagged = other.cmd("o3", `UID STORE 1 +FLAGS.SILENT (\Deleted)`)
	require.Contains(t, tagged, "OK")
	_, tagged = other.cmd("o4", "EXPUNGE")
	require.Contains(t, tagged, "OK")

	// The FETCH's poll finds the expunge and the new message and may send neither.
	untagged, tagged := viewer.cmd("u1", "FETCH 1 (UID)")
	require.Contains(t, tagged, "OK")
	require.Empty(t, expungeSeqs(untagged))
	require.Zero(t, existsCount(untagged))

	_, tagged = viewer.cmd("u2", `STORE 1:* +FLAGS.SILENT (\Flagged)`)
	require.Contains(t, tagged, "OK")

	untagged, tagged = viewer.cmd("u3", "FETCH 1:* (UID)")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"2:2", "3:3"}, seqUIDPairs(untagged), "the client's messages are UIDs 1..3")

	// UID FETCH may send the EXPUNGE and EXISTS (and the STORE's flags), after its
	// responses.
	untagged, tagged = viewer.cmd("u4", "UID FETCH 1:* (UID)")
	require.Contains(t, tagged, "OK")
	t.Logf("UID FETCH untagged: %v", untagged)
	require.Equal(t, []string{"1"}, expungeSeqs(untagged))
	require.Equal(t, 1, existsCount(untagged))
	responses := untagged[:firstIndexOfResponse(untagged, "EXPUNGE")]
	require.Equal(t, []string{"2:2", "3:3"}, seqUIDPairs(responses), "UID 4 has no number the client knows")

	untagged, tagged = viewer.cmd("u5", "FETCH 1:* (UID FLAGS)")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"1:2", "2:3", "3:4"}, seqUIDPairs(untagged))
	require.NotContains(t, flagsOfUID(t, viewer, "4"), `\Flagged`, "STORE 1:* named the client's messages, not UID 4")
	require.Contains(t, flagsOfUID(t, viewer, "3"), `\Flagged`)
}

// TestIMAP_Poll_PhantomDoesNotExpungeTheNextMessage: a message created and expunged
// between two polls is never reported, and the poll cursor must still move past its
// expunge. Left behind, the message counted as one the client knew, and the next poll
// reported its expunge at the number of the message after it: the client lost a
// message it had just been told about, and got it back as a new one.
func TestIMAP_Poll_PhantomDoesNotExpungeTheNextMessage(t *testing.T) {
	viewer, other := twoSessions(t, 3)
	other.append("o1", "INBOX", msg(4)) // UID 4, expunged below
	other.append("o2", "INBOX", msg(5)) // UID 5
	_, tagged := other.cmd("o3", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	_, tagged = other.cmd("o4", `UID STORE 4 +FLAGS.SILENT (\Deleted)`)
	require.Contains(t, tagged, "OK")
	_, tagged = other.cmd("o5", "UID EXPUNGE 4")
	require.Contains(t, tagged, "OK")

	untagged, tagged := viewer.cmd("p1", "NOOP")
	require.Contains(t, tagged, "OK")
	t.Logf("NOOP 1: %v", untagged)
	require.Empty(t, expungeSeqs(untagged))
	require.Contains(t, untagged, "* 4 EXISTS")

	untagged, tagged = viewer.cmd("p2", "NOOP")
	require.Contains(t, tagged, "OK")
	require.Empty(t, untagged, "nothing has changed since the last NOOP")

	untagged, tagged = viewer.cmd("p3", "FETCH 4 (UID)")
	require.Contains(t, tagged, "OK")
	require.Equal(t, []string{"4:5"}, seqUIDPairs(untagged))
}

// TestIMAP_SessionSeqNums_StarStopsAtTheClientsLastMessage: "*" and a range ending at
// the client's last message name the messages the client knows, however many the
// database counts by then. A restored message keeps the created_modseq it had before
// its expunge, so until the next poll it sits below the session's cursor without the
// client having been told about it; STORE 1:* must not reach it.
func TestIMAP_SessionSeqNums_StarStopsAtTheClientsLastMessage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	t.Cleanup(server.Close)
	ctx := context.Background()

	other := dialRaw(t, server.Address)
	t.Cleanup(func() { other.conn.Close() })
	other.login(account)
	setupInboxWith(t, other, 4)
	_, tagged := other.cmd("o1", `UID STORE 4 +FLAGS.SILENT (\Deleted)`)
	require.Contains(t, tagged, "OK")
	_, tagged = other.cmd("o2", "EXPUNGE")
	require.Contains(t, tagged, "OK")

	viewer := dialRaw(t, server.Address)
	t.Cleanup(func() { viewer.conn.Close() })
	viewer.login(account)
	untagged, tagged := viewer.cmd("v1", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	require.Contains(t, untagged, "* 3 EXISTS")

	inbox := "INBOX"
	restored, err := server.ResilientDB.RestoreMessagesWithRetry(ctx, db.RestoreMessagesParams{Email: account.Email, MailboxPath: &inbox})
	require.NoError(t, err)
	require.Equal(t, int64(1), restored)

	_, tagged = viewer.cmd("v2", `STORE 1:* +FLAGS.SILENT (\Flagged)`)
	require.Contains(t, tagged, "OK")

	require.Contains(t, flagsOfUID(t, other, "3"), `\Flagged`)
	require.NotContains(t, flagsOfUID(t, other, "5"), `\Flagged`,
		"the restored message (UID 5) is not one of the three the client knew")
}

// TestIMAP_SessionSeqNums_UIDStarIsTheMailboxsLastMessage: UID "*" is "the unique
// identifier of the last message in the mailbox" (RFC 9051 §9, seq-number). A message
// delivered since the session's last poll is in the mailbox, so UID 4:* names it alone,
// not also the message before it.
func TestIMAP_SessionSeqNums_UIDStarIsTheMailboxsLastMessage(t *testing.T) {
	viewer, other := twoSessions(t, 3)
	other.append("o1", "INBOX", msg(4)) // UID 4

	untagged, tagged := viewer.cmd("u1", "UID SEARCH UID 4:*")
	require.Contains(t, tagged, "OK")
	require.Contains(t, untagged, "* SEARCH 4")
	require.NotContains(t, untagged, "* SEARCH 3 4")
}
