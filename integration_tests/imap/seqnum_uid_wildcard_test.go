//go:build integration

package imap_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func firstResponseWithPrefix(t *testing.T, untagged []string, prefix string) string {
	t.Helper()
	for _, line := range untagged {
		if line == prefix || strings.HasPrefix(line, prefix+" ") {
			return line
		}
	}
	t.Fatalf("no %q response in untagged lines: %v", prefix, untagged)
	return ""
}

// TestIMAP_SearchUIDWildcard_AfterUnannouncedArrivals verifies RFC 9051 §6.4.4 / §9
// ("*" in a UID set denotes the largest UID currently in use in the mailbox, not the
// session's sequence-view tail) for the RFC 4549 sync pattern `UID <uidnext>:*` when
// messages arrive after SELECT.
func TestIMAP_SearchUIDWildcard_AfterUnannouncedArrivals(t *testing.T) {
	newArrivalsSetup := func(t *testing.T) *rawConn {
		t.Helper()
		viewer, other := twoSessions(t, 3) // INBOX has UIDs 1..3 (UIDNEXT=4) in viewer's view
		other.append("o1", "INBOX", msg(4))
		other.append("o2", "INBOX", msg(5))
		return viewer
	}

	t.Run("UID_SEARCH_UID_range", func(t *testing.T) {
		viewer := newArrivalsSetup(t)
		untagged, tagged := viewer.cmd("s1", "UID SEARCH UID 4:*")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SEARCH 4 5", firstResponseWithPrefix(t, untagged, "* SEARCH"),
			"UID 4:* must resolve * to highest live UID (5), not view tail (3)")
	})

	t.Run("UID_SEARCH_UID_star_vs_seq_star", func(t *testing.T) {
		viewer, other := twoSessions(t, 3)
		other.append("o1", "INBOX", msg(4))
		other.append("o2", "INBOX", msg(5))

		// Check sequence '*' and UID '*' on fresh pre-EXISTS views so neither command's
		// post-command Poll advances the other's view.
		untagged, tagged := viewer.cmd("s1", "UID SEARCH *")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SEARCH 3", firstResponseWithPrefix(t, untagged, "* SEARCH"),
			"sequence '*' must remain the session view's last message (UID 3)")

		viewer2 := newArrivalsSetup(t)
		untagged, tagged = viewer2.cmd("s2", "UID SEARCH UID *")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SEARCH 5", firstResponseWithPrefix(t, untagged, "* SEARCH"),
			"UID '*' must resolve to the mailbox's highest live UID (5)")
	})

	t.Run("SEQ_SEARCH_UID_range_omits_unannounced", func(t *testing.T) {
		viewer := newArrivalsSetup(t)
		untagged, tagged := viewer.cmd("s1", "SEARCH UID 4:*")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SEARCH", firstResponseWithPrefix(t, untagged, "* SEARCH"),
			"SEARCH UID 4:* before EXISTS must not falsely match UID 3 or emit unannounced sequence numbers")
	})

	t.Run("UID_SORT_UID_range", func(t *testing.T) {
		viewer := newArrivalsSetup(t)
		untagged, tagged := viewer.cmd("so1", "UID SORT (ARRIVAL) UTF-8 UID 4:*")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SORT 4 5", firstResponseWithPrefix(t, untagged, "* SORT"))
	})

	t.Run("UID_THREAD_UID_range", func(t *testing.T) {
		viewer := newArrivalsSetup(t)
		untagged, tagged := viewer.cmd("th1", "UID THREAD REFERENCES UTF-8 UID 4:*")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* THREAD (4)(5)", firstResponseWithPrefix(t, untagged, "* THREAD"))
	})
}

// TestIMAP_SearchUIDWildcard_AfterForeignExpungeOfHighestUID verifies that when
// another session expunges the highest UID, `UID *` resolves to the highest
// remaining live UID rather than the expunged UID held in the session's seqView.
func TestIMAP_SearchUIDWildcard_AfterForeignExpungeOfHighestUID(t *testing.T) {
	tailExpungeSetup := func(t *testing.T) *rawConn {
		t.Helper()
		viewer, other := twoSessions(t, 5) // INBOX has UIDs 1..5 in viewer's view
		_, tagged := other.cmd("o1", "SELECT INBOX")
		require.Contains(t, tagged, "OK")
		_, tagged = other.cmd("o2", `UID STORE 5 +FLAGS.SILENT (\Deleted)`)
		require.Contains(t, tagged, "OK")
		_, tagged = other.cmd("o3", "EXPUNGE")
		require.Contains(t, tagged, "OK")
		return viewer
	}

	t.Run("UID_SEARCH_UID_star", func(t *testing.T) {
		viewer := tailExpungeSetup(t)
		untagged, tagged := viewer.cmd("s1", "UID SEARCH UID *")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SEARCH 4", firstResponseWithPrefix(t, untagged, "* SEARCH"),
			"UID * must match highest remaining live UID (4), not expunged UID 5")
	})

	t.Run("UID_SEARCH_UID_99_star", func(t *testing.T) {
		viewer := tailExpungeSetup(t)
		untagged, tagged := viewer.cmd("s1", "UID SEARCH UID 99:*")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SEARCH 4", firstResponseWithPrefix(t, untagged, "* SEARCH"),
			"UID 99:* (normalized to 4:99) must match highest live UID 4")
	})

	t.Run("SEQ_SEARCH_UID_star_before_poll", func(t *testing.T) {
		viewer := tailExpungeSetup(t)
		untagged, tagged := viewer.cmd("s1", "SEARCH UID *")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SEARCH 4", firstResponseWithPrefix(t, untagged, "* SEARCH"),
			"UID '*' is live UID 4 (sequence 4)")
	})

	t.Run("SEQ_SEARCH_NOT_UID_star_before_poll", func(t *testing.T) {
		viewer := tailExpungeSetup(t)
		untagged, tagged := viewer.cmd("s1", "SEARCH NOT UID *")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SEARCH 1 2 3", firstResponseWithPrefix(t, untagged, "* SEARCH"),
			"NOT UID * must exclude live UID 4, returning 1 2 3")
	})

	t.Run("SEQ_SEARCH_star_stays_expunged_slot_while_UID_star_is_live", func(t *testing.T) {
		viewer := tailExpungeSetup(t)

		// Sequence SEARCH withholds EXPUNGE, so viewer retains slots 1..5 across these commands.
		untagged, tagged := viewer.cmd("s1", "SEARCH *")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SEARCH", firstResponseWithPrefix(t, untagged, "* SEARCH"),
			"sequence '*' is slot 5 (expunged), so SEARCH * matches nothing")

		untagged, tagged = viewer.cmd("s2", "SEARCH UID *")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SEARCH 4", firstResponseWithPrefix(t, untagged, "* SEARCH"),
			"UID '*' is live UID 4 (sequence 4)")

		untagged, tagged = viewer.cmd("s3", "SEARCH NOT UID *")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SEARCH 1 2 3", firstResponseWithPrefix(t, untagged, "* SEARCH"),
			"NOT UID * must exclude live UID 4, returning 1 2 3")
	})
}

// TestIMAP_SearchUIDWildcard_EmptyAtSelectThenArrival verifies that when a mailbox
// is empty at SELECT (view > 0 with 0 messages in the view) and UID 1 subsequently
// arrives, `UID 1:*` and `UID *` resolve `*` to live UID 1 rather than treating the
// mailbox as having no wildcard endpoint.
func TestIMAP_SearchUIDWildcard_EmptyAtSelectThenArrival(t *testing.T) {
	t.Run("empty_mailbox_stays_empty_for_UID_star", func(t *testing.T) {
		viewer, _ := twoSessions(t, 0)
		untagged, tagged := viewer.cmd("s0", "UID SEARCH UID *")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SEARCH", firstResponseWithPrefix(t, untagged, "* SEARCH"))
	})

	t.Run("UID_1_star_after_first_arrival", func(t *testing.T) {
		viewer, other := twoSessions(t, 0) // empty INBOX at SELECT (view modseq >= 1)
		other.append("o1", "INBOX", msg(1))

		untagged, tagged := viewer.cmd("s1", "UID SEARCH UID 1:*")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SEARCH 1", firstResponseWithPrefix(t, untagged, "* SEARCH"),
			"UID 1:* must find newly arrived UID 1 even when mailbox was empty at SELECT")
	})

	t.Run("UID_star_after_first_arrival", func(t *testing.T) {
		viewer, other := twoSessions(t, 0)
		other.append("o1", "INBOX", msg(1))

		untagged, tagged := viewer.cmd("s1", "UID SEARCH UID *")
		require.Contains(t, tagged, "OK")
		require.Equal(t, "* SEARCH 1", firstResponseWithPrefix(t, untagged, "* SEARCH"),
			"UID * must find newly arrived UID 1 even when mailbox was empty at SELECT")
	})
}
