//go:build integration

package imap_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// firstIndexOfResponse returns the position of the first untagged response of
// the given kind ("EXISTS", "EXPUNGE", ...), or -1 when absent.
func firstIndexOfResponse(untagged []string, kind string) int {
	for i, l := range untagged {
		parts := strings.Fields(l)
		if len(parts) >= 3 && parts[0] == "*" && strings.EqualFold(parts[2], kind) {
			return i
		}
	}
	return -1
}

// fetchedUID parses the UID out of a `* n FETCH (UID x)` response for seqNum.
func fetchedUID(t *testing.T, untagged []string, seqNum int) string {
	t.Helper()
	want := "* " + strconv.Itoa(seqNum) + " FETCH "
	for _, l := range untagged {
		if !strings.HasPrefix(strings.ToUpper(l), strings.ToUpper(want)) {
			continue
		}
		fields := strings.Fields(strings.NewReplacer("(", " ", ")", " ").Replace(l))
		for i, f := range fields {
			if strings.EqualFold(f, "UID") && i+1 < len(fields) {
				return fields[i+1]
			}
		}
	}
	t.Fatalf("no `* %d FETCH (UID ...)` in %v", seqNum, untagged)
	return ""
}

// TestIMAP_Poll_ExistsNotAnnouncedAheadOfWithheldExpunge pins the ordering
// invariant of a single poll: a client is never handed a message count that
// does not match the sequence space it has already been told about.
//
// RFC 3501 §7.4.1 forbids EXPUNGE responses during FETCH/STORE/SEARCH, so
// go-imap polls those commands with allowExpunge=false, and SessionTracker.Poll
// then emits the leading non-expunge updates and stops at the first queued
// expunge. If the poll queues the EXISTS *before* the EXPUNGE, the wire carries
// the new total while the expunge stays behind: the client applies a larger
// count to a stale sequence space and silently desyncs, and only learns about
// the removal on some later NOOP.
//
// Expunge sequence numbers are computed by db.PollMailbox in the client's
// *pre-poll* view (created_modseq <= sinceModSeq), so they are only meaningful
// before the count is grown — one more reason the EXPUNGEs must be queued first.
func TestIMAP_Poll_ExistsNotAnnouncedAheadOfWithheldExpunge(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	// Viewer connection, in sync with INBOX at 10 messages (UIDs 1..10).
	viewer := dialRaw(t, server.Address)
	defer viewer.conn.Close()
	viewer.login(account)
	setupInboxWith(t, viewer, 10)

	// A second connection appends two messages and expunges UID 3, all within a
	// single poll window of the viewer. The live count goes 10 -> 11.
	mutator := dialRaw(t, server.Address)
	defer mutator.conn.Close()
	mutator.login(account)
	mutator.append("m11", "INBOX", msg(11))
	mutator.append("m12", "INBOX", msg(12))
	_, tagged := mutator.cmd("msel", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	_, tagged = mutator.cmd("mdel", `UID STORE 3 +FLAGS (\Deleted)`)
	require.Contains(t, tagged, "OK")
	_, tagged = mutator.cmd("mexp", "UID EXPUNGE 3")
	require.Contains(t, tagged, "OK")

	// FETCH polls with allowExpunge=false, so the expunge cannot go out here.
	fetchUntagged, tagged := viewer.cmd("f", "FETCH 1 (UID)")
	require.Contains(t, tagged, "OK")
	t.Logf("FETCH untagged (%d): %v", len(fetchUntagged), fetchUntagged)

	// NOOP polls with allowExpunge=true and drains whatever was held back.
	noopUntagged, tagged := viewer.cmd("n", "NOOP")
	require.Contains(t, tagged, "OK")
	t.Logf("NOOP untagged (%d): %v", len(noopUntagged), noopUntagged)

	// The expunge really was deferred past the FETCH.
	require.Equal(t, []string{"3"}, expungeSeqs(noopUntagged),
		"the withheld `* 3 EXPUNGE` must arrive on the next expunge-permitting poll")

	// THE INVARIANT: since the EXPUNGE could not be sent during the FETCH, the
	// new count must not be sent during the FETCH either.
	require.Equal(t, 0, existsCount(fetchUntagged),
		"FETCH announced a new EXISTS count while withholding `* 3 EXPUNGE`; "+
			"the client's sequence-number map is now silently desynced")

	// The deferred batch is ordered EXPUNGE-then-EXISTS, and the count is
	// actually delivered (a client that never hears about new mail is its own
	// bug — the EXISTS must be deferred, not dropped).
	require.Equal(t, 1, existsCount(noopUntagged), "the new count must still be delivered")
	require.Less(t, firstIndexOfResponse(noopUntagged, "EXPUNGE"), firstIndexOfResponse(noopUntagged, "EXISTS"),
		"EXPUNGE must precede EXISTS so the count applies to the updated sequence space")
	require.Contains(t, noopUntagged[firstIndexOfResponse(noopUntagged, "EXISTS")], "11 EXISTS")

	// The sequence space the client now holds matches the server's: UIDs
	// 1,2,4..12 => seq 10 is UID 11 and seq 11 is UID 12.
	probe, tagged := viewer.cmd("p", "FETCH 10:11 (UID)")
	require.Contains(t, tagged, "OK")
	t.Logf("probe untagged (%d): %v", len(probe), probe)
	require.Equal(t, "11", fetchedUID(t, probe, 10))
	require.Equal(t, "12", fetchedUID(t, probe, 11))
}

// TestIMAP_Poll_ExpungePrecedesExistsInSameBatch covers the same ordering rule on
// the expunge-permitting path (NOOP/IDLE), where nothing is withheld and the whole
// batch reaches the client at once.
//
// Queueing the count-up before the expunges does not just misorder the batch, it
// duplicates it: an EXISTS ahead of the expunges, then the reconciliation EXISTS
// behind them. That leading count is a lie while it stands — it counts the new
// messages but still counts the message the client has not been told is gone — and
// a duplicate EXISTS straddling an EXPUNGE is the "phantom EXISTS" shape that makes
// Apple Mail blank out adjacent rows.
func TestIMAP_Poll_ExpungePrecedesExistsInSameBatch(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	viewer := dialRaw(t, server.Address)
	defer viewer.conn.Close()
	viewer.login(account)
	setupInboxWith(t, viewer, 10)

	mutator := dialRaw(t, server.Address)
	defer mutator.conn.Close()
	mutator.login(account)
	mutator.append("m11", "INBOX", msg(11))
	mutator.append("m12", "INBOX", msg(12))
	_, tagged := mutator.cmd("msel", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	_, tagged = mutator.cmd("mdel", `UID STORE 3 +FLAGS (\Deleted)`)
	require.Contains(t, tagged, "OK")
	_, tagged = mutator.cmd("mexp", "UID EXPUNGE 3")
	require.Contains(t, tagged, "OK")

	// The viewer's first poll of this window permits expunges, so the whole
	// batch goes out here.
	untagged, tagged := viewer.cmd("n", "NOOP")
	require.Contains(t, tagged, "OK")
	t.Logf("NOOP untagged (%d): %v", len(untagged), untagged)

	require.Equal(t, []string{"3"}, expungeSeqs(untagged), "exactly one EXPUNGE for UID 3")
	require.Equal(t, 1, existsCount(untagged),
		"exactly one EXISTS: a count queued ahead of the expunges is both premature and duplicated")
	require.Less(t, firstIndexOfResponse(untagged, "EXPUNGE"), firstIndexOfResponse(untagged, "EXISTS"),
		"EXPUNGE must precede EXISTS so the new count applies to the updated sequence space")
}
