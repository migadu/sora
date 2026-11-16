//go:build integration

package imap_test

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

var highestModSeqCodeRe = regexp.MustCompile(`^\* OK \[HIGHESTMODSEQ (\d+)\]`)

// highestModSeqCodes returns the values of the untagged OK [HIGHESTMODSEQ n]
// responses among untagged.
func highestModSeqCodes(t *testing.T, untagged []string) []uint64 {
	t.Helper()
	var values []uint64
	for _, line := range untagged {
		if m := highestModSeqCodeRe.FindStringSubmatch(line); m != nil {
			v, err := strconv.ParseUint(m[1], 10, 64)
			if err != nil {
				t.Fatalf("HIGHESTMODSEQ in %q: %v", line, err)
			}
			values = append(values, v)
		}
	}
	return values
}

// maxModSeqItem returns the highest MODSEQ (n) FETCH data item among untagged.
func maxModSeqItem(t *testing.T, untagged []string) uint64 {
	t.Helper()
	var highest uint64
	for _, line := range untagged {
		if m := modSeqItemRe.FindStringSubmatch(line); m != nil {
			v, err := strconv.ParseUint(m[1], 10, 64)
			if err != nil {
				t.Fatalf("MODSEQ in %q: %v", line, err)
			}
			highest = max(highest, v)
		}
	}
	return highest
}

// selectHighestModSeq runs a plain SELECT and returns the HIGHESTMODSEQ it reported.
func selectHighestModSeq(t *testing.T, c *rawIMAP, mailbox string) uint64 {
	t.Helper()
	untagged, _ := c.do("SELECT " + mailbox)
	codes := highestModSeqCodes(t, untagged)
	if len(codes) != 1 {
		t.Fatalf("SELECT %s: want one HIGHESTMODSEQ, got %q", mailbox, untagged)
	}
	return codes[0]
}

// TestIMAP_FirstCondStoreEnablingCommandReturnsHighestModSeq checks RFC 7162
// §3.1: "A first CONDSTORE enabling command executed in the session with a
// mailbox selected MUST cause the server to return HIGHESTMODSEQ (Section
// 3.1.2.1) for the mailbox (if any is selected), unless the server has sent a
// NOMODSEQ (Section 3.1.2.2) response code when the currently selected mailbox
// was selected."
//
// The mailbox changes in another session between SELECT and the enabling
// FETCH, so the value from SELECT is stale by then.
func TestIMAP_FirstCondStoreEnablingCommandReturnsHighestModSeq(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	seedMessage(t, server, account)
	seedMessage(t, server, account)

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	selected := selectHighestModSeq(t, c, "INBOX")

	changeFlagFromAnotherSession(t, server, account)

	untagged, _ := c.do("FETCH 1:2 (FLAGS MODSEQ)")
	codes := highestModSeqCodes(t, untagged)
	if len(codes) != 1 {
		t.Fatalf("first CONDSTORE enabling FETCH: want one HIGHESTMODSEQ response, got %q", untagged)
	}
	current := maxModSeqItem(t, untagged)
	if current <= selected {
		t.Fatalf("FETCH MODSEQ items %q do not show the other session's change (SELECT HIGHESTMODSEQ %d)", untagged, selected)
	}
	if codes[0] != current {
		t.Errorf("HIGHESTMODSEQ = %d, want %d, the highest MODSEQ the FETCH reported (SELECT said %d): %q", codes[0], current, selected, untagged)
	}

	// Only the first enabling command returns it.
	untagged, _ = c.do("FETCH 1 (MODSEQ)")
	if codes := highestModSeqCodes(t, untagged); len(codes) != 0 {
		t.Errorf("second enabling command: want no HIGHESTMODSEQ, got %q", untagged)
	}
}

// TestIMAP_FirstCondStoreEnablingCommandHighestModSeqBelowDelayedExpunge checks
// that the HIGHESTMODSEQ the first enabling command returns does not cover a
// change still queued for the client. A FETCH must not deliver an EXPUNGE (RFC
// 3501 §7.4.1), and the flag change queued behind it waits too; yet the client
// adopts the code "even if it has seen higher mod-sequences" (RFC 7162 §6), so a
// value covering them would let it skip them when it resynchronizes.
func TestIMAP_FirstCondStoreEnablingCommandHighestModSeqBelowDelayedExpunge(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	seedMessage(t, server, account)
	seedMessage(t, server, account)

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	selectHighestModSeq(t, c, "INBOX")

	// Another session expunges message 1, then flags the former message 2.
	other := dialRawIMAP(t, server.Address)
	other.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	other.do("SELECT INBOX (CONDSTORE)")
	other.do(`STORE 1 +FLAGS.SILENT (\Deleted)`)
	other.do("EXPUNGE")
	untagged, _ := other.do(`STORE 1 +FLAGS (\Flagged)`)
	flagModSeq := maxModSeqItem(t, untagged)
	if flagModSeq == 0 {
		t.Fatalf("other session STORE: no MODSEQ in %q", untagged)
	}
	other.do("LOGOUT")

	untagged, _ = c.do("FETCH 2 (FLAGS MODSEQ)")
	codes := highestModSeqCodes(t, untagged)
	if len(codes) != 1 {
		t.Fatalf("first CONDSTORE enabling FETCH: want one HIGHESTMODSEQ response, got %q", untagged)
	}
	if codes[0] >= flagModSeq {
		t.Errorf("HIGHESTMODSEQ = %d covers the queued EXPUNGE and the flag change (MODSEQ %d) behind it: %q", codes[0], flagModSeq, untagged)
	}

	// The queued changes arrive at the next command that may expunge.
	untagged, _ = c.do("NOOP")
	if !hasLinePrefix(untagged, "* 1 EXPUNGE") {
		t.Errorf("NOOP: want the queued * 1 EXPUNGE, got %q", untagged)
	}
}

// TestIMAP_FirstCondStoreEnablingCommandHighestModSeqQueuedFlagDroppedByNotify
// checks that when a flag change is queued behind a withheld EXPUNGE while
// FlagChange is still allowed, and NOTIFY later suppresses FlagChange before
// the tracker drains, the drained-and-discarded flag update still holds back
// the HIGHESTMODSEQ returned by the first CONDSTORE enabling command.
func TestIMAP_FirstCondStoreEnablingCommandHighestModSeqQueuedFlagDroppedByNotify(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	for _, mode := range []string{"notify_set", "notify_none_expunge"} {
		t.Run(mode, func(t *testing.T) {
			server, account := common.SetupIMAPServer(t)
			defer server.Close()

			seedMessage(t, server, account)
			seedMessage(t, server, account)

			c := dialRawIMAP(t, server.Address)
			c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
			selected := selectHighestModSeq(t, c, "INBOX")

			// Another session expunges message 1, then flags former message 2 (UID 2).
			other := dialRawIMAP(t, server.Address)
			other.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
			other.do("SELECT INBOX (CONDSTORE)")
			other.do(`STORE 1 +FLAGS.SILENT (\Deleted)`)
			other.do("EXPUNGE")
			untagged, _ := other.do(`STORE 1 +FLAGS (\Flagged)`)
			flagModSeq := maxModSeqItem(t, untagged)
			if flagModSeq <= selected {
				t.Fatalf("other session STORE: want MODSEQ > %d, got %d in %q", selected, flagModSeq, untagged)
			}
			other.do("LOGOUT")

			// FETCH may not expunge (RFC 3501 §7.4.1). Before NOTIFY is used,
			// FlagChangeAllowed() is true, so Poll queues [Expunge(1), FlagUpdate(2)]
			// into sessionTracker and advances currentHighestModSeq to flagModSeq.
			untagged, _ = c.do("FETCH 2 (UID)")
			if hasLinePrefix(untagged, "* 1 EXPUNGE") {
				t.Fatalf("FETCH 2 (UID): unexpected EXPUNGE in %q", untagged)
			}
			if strings.Contains(strings.Join(untagged, "\n"), `\Flagged`) {
				t.Fatalf("FETCH 2 (UID): unexpected \\Flagged before tracker drain: %q", untagged)
			}

			var enablingCmd string
			switch mode {
			case "notify_set":
				// NOTIFY SET disables FlagChange, then its implicit NOOP drains the
				// tracker: * 1 EXPUNGE is sent while the queued FlagUpdate is dropped.
				untagged, _ = c.do("NOTIFY SET (SELECTED (MessageNew MessageExpunge))")
				if !hasLinePrefix(untagged, "* 1 EXPUNGE") {
					t.Fatalf("NOTIFY SET: want * 1 EXPUNGE, got %q", untagged)
				}
				if strings.Contains(strings.Join(untagged, "\n"), `\Flagged`) {
					t.Fatalf("NOTIFY SET: FlagChange should have been suppressed: %q", untagged)
				}
				enablingCmd = "ENABLE CONDSTORE"
			case "notify_none_expunge":
				// NOTIFY NONE suppresses unsolicited events without draining the
				// tracker; EXPUNGE then forces the tracker to flush * 1 EXPUNGE while
				// WriteMessageFlags drops the queued FlagUpdate.
				untagged, _ = c.do("NOTIFY NONE")
				if strings.Contains(strings.Join(untagged, "\n"), `\Flagged`) {
					t.Fatalf("NOTIFY NONE: unexpected \\Flagged: %q", untagged)
				}
				untagged, _ = c.do("EXPUNGE")
				if !hasLinePrefix(untagged, "* 1 EXPUNGE") {
					t.Fatalf("EXPUNGE: want * 1 EXPUNGE, got %q", untagged)
				}
				if strings.Contains(strings.Join(untagged, "\n"), `\Flagged`) {
					t.Fatalf("EXPUNGE: FlagChange should have been suppressed: %q", untagged)
				}
				enablingCmd = "FETCH 1 (MODSEQ)"
			}

			first, _ := c.do(enablingCmd)
			if strings.Contains(strings.Join(first, "\n"), `\Flagged`) {
				t.Fatalf("%s: unexpected \\Flagged: %q", enablingCmd, first)
			}
			codes := highestModSeqCodes(t, first)
			if len(codes) != 1 {
				t.Fatalf("%s: want one HIGHESTMODSEQ response, got %q", enablingCmd, first)
			}
			if codes[0] != selected || codes[0] >= flagModSeq {
				t.Errorf("%s: HIGHESTMODSEQ = %d covers dropped queued flag change (MODSEQ %d); want SELECT baseline %d: %q",
					enablingCmd, codes[0], flagModSeq, selected, first)
			}

			// Adopting HIGHESTMODSEQ and resynchronizing from it must still surface
			// the dropped \Flagged update on UID 2.
			resync, _ := c.do(fmt.Sprintf("UID FETCH 1:* (UID FLAGS) (CHANGEDSINCE %d)", codes[0]))
			joined := strings.Join(resync, "\n")
			if !strings.Contains(joined, "UID 2") || !strings.Contains(joined, `\Flagged`) {
				t.Errorf("resync from HIGHESTMODSEQ %d skipped dropped flag on UID 2: %q", codes[0], resync)
			}
		})
	}
}
