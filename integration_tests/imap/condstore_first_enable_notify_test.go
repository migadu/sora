//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// An explicitly filtered FlagChange is consumed without a FETCH response. The
// first-enabling HIGHESTMODSEQ must not acknowledge it as synchronized: RFC7162
// section6 makes the client adopt that value even if it saw higher per-message
// values. Enabling notifications again cannot repair an already consumed delta.
func TestIMAP_FirstCondStoreEnablingCommandBelowFilteredFlagChange(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	for _, mode := range []string{"filtered", "reenabled", "reselected", "none", "none_reenabled", "none_uidexpunge"} {
		t.Run(mode, func(t *testing.T) {
			srv, account := common.SetupIMAPServer(t)
			defer srv.Close()
			seedMessage(t, srv, account)
			seedMessage(t, srv, account)
			c := dialRawIMAP(t, srv.Address)
			c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
			baseline := selectHighestModSeq(t, c, "INBOX")
			cached, _ := c.do("UID FETCH 1:2 (UID FLAGS)")
			if strings.Contains(strings.Join(cached, "\n"), `\Flagged`) {
				t.Fatal("initial cache already has the flag")
			}
			if strings.HasPrefix(mode, "none") {
				c.do("NOTIFY NONE")
			} else {
				c.do("NOTIFY SET (selected (MessageNew MessageExpunge))")
			}

			other := dialRawIMAP(t, srv.Address)
			other.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
			other.do("SELECT INBOX (CONDSTORE)")
			changed, _ := other.do(`UID STORE 2 +FLAGS (\Flagged)`)
			flagModSeq := maxModSeqItem(t, changed)
			if flagModSeq <= baseline {
				t.Fatalf("other STORE did not change metadata: %q", changed)
			}
			// NOOP runs the selected pipeline with FlagChange disabled. Under
			// NOTIFY NONE, EXPUNGE commands still force it to report command
			// results, even though no message is currently marked Deleted.
			// The flag update is consumed without reaching this client's cache.
			syncCommand := "NOOP"
			if strings.HasPrefix(mode, "none") {
				syncCommand = "EXPUNGE"
			}
			if mode == "none_uidexpunge" {
				syncCommand = "UID EXPUNGE 1:2"
			}
			filtered, _ := c.do(syncCommand)
			if strings.Contains(strings.Join(filtered, "\n"), `\Flagged`) {
				t.Fatalf("FlagChange was not filtered: %q", filtered)
			}
			if mode == "reenabled" || mode == "reselected" || mode == "none_reenabled" {
				c.do("NOTIFY SET (selected (MessageNew MessageExpunge FlagChange))")
				c.do("NOOP")
			}

			if mode == "reselected" {
				// A new selection establishes a fresh baseline and must clear
				// the earlier selection's gap. No command has enabled CONDSTORE
				// on this connection yet.
				baseline = selectHighestModSeq(t, c, "INBOX")
				changed, _ = other.do(`UID STORE 2 +FLAGS (\Answered)`)
				flagModSeq = maxModSeqItem(t, changed)
				if flagModSeq <= baseline {
					t.Fatalf("new selection's STORE did not change metadata: %q", changed)
				}
				c.do("NOOP")
			}

			first, _ := c.do("UID FETCH 1 (UID FLAGS MODSEQ)")
			codes := highestModSeqCodes(t, first)
			if len(codes) != 1 {
				t.Fatalf("first enabling FETCH: want one HIGHESTMODSEQ, got %q", first)
			}
			if mode == "reselected" {
				if codes[0] != flagModSeq {
					t.Fatalf("new selection did not resume its reported watermark: got %d, want %d (SELECT %d): %q", codes[0], flagModSeq, baseline, first)
				}
				return
			}
			if codes[0] != baseline || codes[0] >= flagModSeq {
				t.Errorf("HIGHESTMODSEQ %d covers filtered UID2 change %d; want last reported baseline %d: %q", codes[0], flagModSeq, baseline, first)
			}
			// Adopt the explicit code as a cached client must, then explicitly
			// poll flag differences. The filtered update must still be found.
			resync, _ := c.do(fmt.Sprintf("UID FETCH 1:* (UID FLAGS) (CHANGEDSINCE %d)", codes[0]))
			joined := strings.Join(resync, "\n")
			if !strings.Contains(joined, "UID 2") || !strings.Contains(joined, `\Flagged`) {
				t.Errorf("resync skipped the filtered flag after adopting %d: %q", codes[0], resync)
			}
		})
	}
}
