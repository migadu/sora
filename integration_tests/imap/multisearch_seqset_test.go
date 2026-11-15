//go:build integration

package imap_test

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestIMAP_MultiSearch_SequenceSetsPerMailbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	for _, name := range []string{"SeqA", "SeqB", "SeqEmpty"} {
		c.do("CREATE " + name)
	}
	for name, count := range map[string]int{"SeqA": 3, "SeqB": 1, "INBOX": 4} {
		for i := 0; i < count; i++ {
			c.appendMsg(name, fmt.Sprintf("Subject: %s %d\r\n\r\nbody\r\n", name, i))
		}
	}
	c.do("SELECT SeqA")
	c.do(`STORE 1 +FLAGS (\Deleted)`)
	c.do("EXPUNGE")
	c.do("UNSELECT")
	// SeqA has sequence 1=UID 2, sequence 2=UID 3. SeqB has sequence 1=UID 1.
	// The selected INBOX, when present, has a different highest sequence (4).
	allRe := regexp.MustCompile(`\bALL ([0-9:,]+)`)
	for _, selected := range []bool{false, true} {
		if selected {
			c.do("SELECT INBOX")
		}
		for _, tc := range []struct {
			criteria string
			want     map[string]string
		}{
			{"1", map[string]string{"SeqA": "2", "SeqB": "1"}},
			{"*", map[string]string{"SeqA": "3", "SeqB": "1"}},
			{"UID *", map[string]string{"SeqA": "3", "SeqB": "1"}},
			{"UID 99:*", map[string]string{"SeqA": "3", "SeqB": "1"}},
			{"NOT UID *", map[string]string{"SeqA": "2"}},
			{"OR UID * 1", map[string]string{"SeqA": "2:3", "SeqB": "1"}},
			{"*:1", map[string]string{"SeqA": "2:3", "SeqB": "1"}},
			{"99:*", map[string]string{"SeqA": "3", "SeqB": "1"}},
			{"NOT 1", map[string]string{"SeqA": "3"}},
			{"OR 1 UID 99", map[string]string{"SeqA": "2", "SeqB": "1"}},
		} {
			t.Run(fmt.Sprintf("selected=%v/%s", selected, tc.criteria), func(t *testing.T) {
				parentTest := c.t
				c.t = t
				defer func() { c.t = parentTest }()
				lines, _ := c.do(`ESEARCH IN (mailboxes (SeqA SeqB SeqEmpty)) RETURN (ALL) ` + tc.criteria)
				got := map[string]string{}
				for _, line := range lines {
					if !strings.HasPrefix(line, "* ESEARCH") {
						continue
					}
					mailbox := esearchLineRe.FindStringSubmatch(line)
					all := allRe.FindStringSubmatch(line)
					if mailbox == nil || all == nil {
						t.Fatalf("invalid ESEARCH response: %s", line)
					}
					name := mailbox[1]
					if name == "" {
						name = mailbox[2]
					}
					got[name] = all[1]
				}
				if !reflect.DeepEqual(got, tc.want) {
					t.Errorf("ESEARCH %s = %v, want %v", tc.criteria, got, tc.want)
				}
			})
		}
	}
}

func parseESearchAllByMailbox(t *testing.T, lines []string) map[string]string {
	t.Helper()
	allRe := regexp.MustCompile(`\bALL ([0-9:,]+)`)
	got := map[string]string{}
	for _, line := range lines {
		if !strings.HasPrefix(line, "* ESEARCH") {
			continue
		}
		mailbox := esearchLineRe.FindStringSubmatch(line)
		all := allRe.FindStringSubmatch(line)
		if mailbox == nil || all == nil {
			t.Fatalf("invalid ESEARCH response: %s", line)
		}
		name := mailbox[1]
		if name == "" {
			name = mailbox[2]
		}
		got[name] = all[1]
	}
	return got
}

// TestIMAP_MultiSearch_SelectedSeqView_AfterForeignExpunge verifies that RFC 7377
// ESEARCH on the selected mailbox resolves sequence-set criteria through the
// session's seqView (both before Poll and after FETCH queued Expunge in SessionTracker),
// returning UID 2 rather than live-row-2 (UID 3) and saving {2} into "$".
func TestIMAP_MultiSearch_SelectedSeqView_AfterForeignExpunge(t *testing.T) {
	expungeUID1 := func(t *testing.T) *rawConn {
		t.Helper()
		viewer, other := twoSessions(t, 3)
		_, tagged := other.cmd("o1", "SELECT INBOX")
		require.Contains(t, tagged, "OK")
		_, tagged = other.cmd("o2", `UID STORE 1 +FLAGS.SILENT (\Deleted)`)
		require.Contains(t, tagged, "OK")
		_, tagged = other.cmd("o3", "EXPUNGE")
		require.Contains(t, tagged, "OK")
		return viewer
	}

	t.Run("ESEARCH_2_before_poll", func(t *testing.T) {
		viewer := expungeUID1(t)
		untagged, tagged := viewer.cmd("e1", "ESEARCH 2")
		require.Contains(t, tagged, "OK")
		require.Equal(t, map[string]string{"INBOX": "2"}, parseESearchAllByMailbox(t, untagged),
			"ESEARCH 2 must resolve sequence 2 to UID 2 via seqView")
		require.Equal(t, []string{"1"}, expungeSeqs(untagged))
	})

	t.Run("ESEARCH_IN_selected_SAVE_before_poll", func(t *testing.T) {
		viewer := expungeUID1(t)
		untagged, tagged := viewer.cmd("e1", "ESEARCH IN (selected) RETURN (ALL SAVE) 2")
		require.Contains(t, tagged, "OK")
		require.Equal(t, map[string]string{"INBOX": "2"}, parseESearchAllByMailbox(t, untagged))
		require.Equal(t, []string{"1"}, expungeSeqs(untagged))

		untagged, tagged = viewer.cmd("f1", "UID FETCH $ (UID)")
		require.Contains(t, tagged, "OK")
		require.Equal(t, []string{"1:2"}, seqUIDPairs(untagged),
			"$ must hold UID 2 (now at sequence 1 after EXPUNGE), not UID 3")
	})

	t.Run("ESEARCH_2_after_queued_expunge", func(t *testing.T) {
		viewer := expungeUID1(t)
		// FETCH triggers Poll(allowExpunge: false), queuing Expunge(1) in SessionTracker.
		untagged, tagged := viewer.cmd("f0", "FETCH 1 (UID)")
		require.Contains(t, tagged, "OK")
		require.Empty(t, expungeSeqs(untagged))

		untagged, tagged = viewer.cmd("e1", "ESEARCH 2")
		require.Contains(t, tagged, "OK")
		require.Equal(t, map[string]string{"INBOX": "2"}, parseESearchAllByMailbox(t, untagged))
		require.Equal(t, []string{"1"}, expungeSeqs(untagged))
	})

	t.Run("ESEARCH_IN_selected_SAVE_after_queued_expunge", func(t *testing.T) {
		viewer := expungeUID1(t)
		untagged, tagged := viewer.cmd("f0", "FETCH 1 (UID)")
		require.Contains(t, tagged, "OK")
		require.Empty(t, expungeSeqs(untagged))

		untagged, tagged = viewer.cmd("e1", "ESEARCH IN (selected) RETURN (ALL SAVE) 2")
		require.Contains(t, tagged, "OK")
		require.Equal(t, map[string]string{"INBOX": "2"}, parseESearchAllByMailbox(t, untagged))
		require.Equal(t, []string{"1"}, expungeSeqs(untagged))

		untagged, tagged = viewer.cmd("f1", "UID FETCH $ (UID)")
		require.Contains(t, tagged, "OK")
		require.Equal(t, []string{"1:2"}, seqUIDPairs(untagged))
	})
}

// TestIMAP_MultiSearch_SelectedSeqView_AfterUnannouncedAppend verifies that ESEARCH
// on the selected mailbox clamps '*' and rejects sequence numbers > clientCount
// before EXISTS has announced the new arrival.
func TestIMAP_MultiSearch_SelectedSeqView_AfterUnannouncedAppend(t *testing.T) {
	t.Run("ESEARCH_4_exceeds_clientCount", func(t *testing.T) {
		viewer, other := twoSessions(t, 3)
		other.append("o1", "INBOX", msg(4))

		untagged, tagged := viewer.cmd("e1", "ESEARCH 4")
		require.Contains(t, tagged, "OK")
		require.Equal(t, map[string]string{}, parseESearchAllByMailbox(t, untagged),
			"sequence 4 > clientCount (3) must match nothing before EXISTS")
		require.Contains(t, untagged, "* 4 EXISTS")
	})

	t.Run("ESEARCH_star_clamps_to_clientCount", func(t *testing.T) {
		viewer, other := twoSessions(t, 3)
		other.append("o1", "INBOX", msg(4))

		untagged, tagged := viewer.cmd("e1", "ESEARCH *")
		require.Contains(t, tagged, "OK")
		require.Equal(t, map[string]string{"INBOX": "3"}, parseESearchAllByMailbox(t, untagged),
			"sequence '*' must resolve to client's last message (UID 3), not unannounced UID 4")
		require.Contains(t, untagged, "* 4 EXISTS")
	})
}

// TestIMAP_MultiSearch_PersonalScope_SelectedUsesSeqViewUnselectedUsesLive verifies
// that a multi-mailbox ESEARCH (such as IN (personal)) decodes sequence sets via
// seqView on the selected mailbox while numbering unselected mailboxes against live rows.
func TestIMAP_MultiSearch_PersonalScope_SelectedUsesSeqViewUnselectedUsesLive(t *testing.T) {
	t.Run("foreign_expunge_in_selected_INBOX_and_unselected_Archive", func(t *testing.T) {
		viewer, other := twoSessions(t, 3) // INBOX selected in viewer with UIDs 1, 2, 3

		// Populate unselected "Archive" (created by default) with 2 live messages
		// (UIDs 2 and 3 after expunging UID 1).
		for i := 1; i <= 3; i++ {
			other.append(fmt.Sprintf("ap%d", i), "Archive", msg(i))
		}
		_, tagged := other.cmd("a1", "SELECT Archive")
		require.Contains(t, tagged, "OK")
		_, tagged = other.cmd("a2", `UID STORE 1 +FLAGS.SILENT (\Deleted)`)
		require.Contains(t, tagged, "OK")
		_, tagged = other.cmd("a3", "EXPUNGE")
		require.Contains(t, tagged, "OK")

		// Foreign-expunge UID 1 in INBOX so INBOX and Archive have identical live UIDs {2, 3},
		// while viewer's seqView for INBOX still numbers UID 2 as sequence 2.
		_, tagged = other.cmd("i1", "SELECT INBOX")
		require.Contains(t, tagged, "OK")
		_, tagged = other.cmd("i2", `UID STORE 1 +FLAGS.SILENT (\Deleted)`)
		require.Contains(t, tagged, "OK")
		_, tagged = other.cmd("i3", "EXPUNGE")
		require.Contains(t, tagged, "OK")

		untagged, tagged := viewer.cmd("e1", "ESEARCH IN (personal) RETURN (ALL) 2")
		require.Contains(t, tagged, "OK")
		require.Equal(t, map[string]string{
			"INBOX":   "2", // seqView sequence 2 = UID 2
			"Archive": "3", // live sequence 2 = UID 3
		}, parseESearchAllByMailbox(t, untagged))
	})

	t.Run("unannounced_arrival_in_selected_INBOX_vs_2_messages_in_Archive", func(t *testing.T) {
		viewer, other := twoSessions(t, 1) // INBOX selected in viewer with clientCount = 1 (UID 1)

		other.append("ap1", "Archive", msg(1))
		other.append("ap2", "Archive", msg(2))

		// Append unannounced UID 2 to INBOX.
		other.append("i1", "INBOX", msg(2))

		untagged, tagged := viewer.cmd("e1", "ESEARCH IN (personal) RETURN (ALL) 2")
		require.Contains(t, tagged, "OK")
		require.Equal(t, map[string]string{
			"Archive": "2", // INBOX omits unannounced sequence 2; Archive has 2 live messages
		}, parseESearchAllByMailbox(t, untagged))
	})
}
