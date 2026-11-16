//go:build integration

package imap_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

var selectUIDValidityRe = regexp.MustCompile(`\[UIDVALIDITY (\d+)\]`)

// clientHighestModSeq is the HIGHESTMODSEQ a client holding current takes from
// one command's untagged responses (RFC 7162 §6): "If the HIGHESTMODSEQ
// response code is received, the client MUST use it even if it has seen higher
// mod-sequences. Otherwise, the client calculates the highest value among all
// MODSEQ FETCH data items received since the last tagged response. If this
// value is bigger than the client's copy of the HIGHESTMODSEQ value, then the
// client MUST use this value as its new HIGHESTMODSEQ value."
func clientHighestModSeq(t *testing.T, untagged []string, current uint64) uint64 {
	t.Helper()
	if codes := highestModSeqCodes(t, untagged); len(codes) > 0 {
		return codes[len(codes)-1]
	}
	return max(current, maxModSeqItem(t, untagged))
}

// TestIMAP_DelayedVanishedHighestModSeq checks RFC 7162 §3.2: "A server
// implementing QRESYNC MUST send untagged events to a client in a way that the
// client doesn't lose any changes in case of connectivity loss. In particular,
// this means that if the server sends MODSEQ FETCH data items while EXPUNGE (or
// VANISHED) replies with lower mod-sequences being delayed, the server MUST
// send the HIGHESTMODSEQ response code with a lower value than the EXPUNGE's
// mod-sequence."
//
// A STORE or FETCH may not send the VANISHED of another session's expunge (RFC
// 9051 §7.5.1), but answers with a higher MODSEQ. If the connection drops
// before the VANISHED arrives, a client that resynchronizes from the value it
// adopted has to learn of the expunge.
func TestIMAP_DelayedVanishedHighestModSeq(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	for _, tt := range []struct {
		name string
		cmd  string
	}{
		{"STORE", `STORE 2 +FLAGS (\Seen)`},
		{"FETCH", "FETCH 2 (FLAGS MODSEQ)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			server, account := common.SetupIMAPServer(t)
			defer server.Close()

			seedMessage(t, server, account)
			seedMessage(t, server, account)
			login := fmt.Sprintf("LOGIN %s %s", account.Email, account.Password)

			c := dialRawIMAP(t, server.Address)
			c.do(login)
			c.do("ENABLE QRESYNC")
			selected, _ := c.do("SELECT INBOX")
			codes := highestModSeqCodes(t, selected)
			if len(codes) != 1 {
				t.Fatalf("SELECT INBOX: want one HIGHESTMODSEQ, got %q", selected)
			}
			highest := codes[0]
			m := selectUIDValidityRe.FindStringSubmatch(strings.Join(selected, "\n"))
			if m == nil {
				t.Fatalf("SELECT INBOX: no UIDVALIDITY in %q", selected)
			}
			uidValidity := m[1]

			// Another session expunges UID 1, then flags UID 2.
			other := dialRawIMAP(t, server.Address)
			other.do(login)
			other.do("SELECT INBOX (CONDSTORE)")
			untagged, _ := other.do(`STORE 1 +FLAGS (\Deleted)`)
			deletedModSeq := maxModSeqItem(t, untagged)
			if deletedModSeq <= highest {
				t.Fatalf("other session STORE: want MODSEQ > %d, got %q", highest, untagged)
			}
			other.do("EXPUNGE")
			other.do(`STORE 1 +FLAGS (\Flagged)`)
			other.do("LOGOUT")

			untagged, _ = c.do(tt.cmd)
			if hasLinePrefix(untagged, "* VANISHED") {
				t.Fatalf("%s: want the VANISHED held back (RFC 9051 §7.5.1), got %q", tt.cmd, untagged)
			}
			if maxModSeqItem(t, untagged) <= deletedModSeq {
				t.Fatalf("%s: want a MODSEQ above the delayed VANISHED, got %q", tt.cmd, untagged)
			}
			// The expunge's mod-sequence is above deletedModSeq.
			if codes := highestModSeqCodes(t, untagged); len(codes) != 1 || codes[0] > deletedModSeq {
				t.Errorf("%s: want one HIGHESTMODSEQ of at most %d, below the delayed VANISHED, got %q", tt.cmd, deletedModSeq, untagged)
			}
			adopted := clientHighestModSeq(t, untagged, highest)

			// The connection drops here. A client resynchronizing from the
			// value it adopted must still learn that UID 1 is gone.
			resync := dialRawIMAP(t, server.Address)
			resync.do(login)
			resync.do("ENABLE QRESYNC")
			resynced, _ := resync.do(fmt.Sprintf("SELECT INBOX (QRESYNC (%s %d))", uidValidity, adopted))
			if !hasLinePrefix(resynced, "* VANISHED (EARLIER) 1") {
				t.Errorf("SELECT INBOX (QRESYNC (%s %d)), from the HIGHESTMODSEQ the client adopted: want * VANISHED (EARLIER) 1, got %q", uidValidity, adopted, resynced)
			}

			// The original connection gets the VANISHED at its next NOOP.
			untagged, _ = c.do("NOOP")
			if !hasLinePrefix(untagged, "* VANISHED 1") {
				t.Errorf("NOOP: want the delayed * VANISHED 1, got %q", untagged)
			}

			// With nothing held back, a STORE's own MODSEQ is a safe value.
			untagged, _ = c.do(`STORE 1 +FLAGS (\Answered)`)
			if maxModSeqItem(t, untagged) == 0 {
				t.Fatalf(`STORE 1 +FLAGS (\Answered): no MODSEQ in %q`, untagged)
			}
			if codes := highestModSeqCodes(t, untagged); len(codes) != 0 {
				t.Errorf(`STORE 1 +FLAGS (\Answered) with nothing held back: want no HIGHESTMODSEQ, got %q`, untagged)
			}
		})
	}
}
