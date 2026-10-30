//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_Rev2DoesNotEnableCondStoreOrQResync: IMAP4rev2 folds in neither
// CONDSTORE nor QRESYNC (RFC 9051 Appendix F; go-imap #104), so a client that
// sent only ENABLE IMAP4rev2 gets no MODSEQ in FETCH (RFC 7162 §3.1) and EXPUNGE
// rather than VANISHED (§3.2.10). One that also enables QRESYNC gets both.
func TestIMAP_Rev2DoesNotEnableCondStoreOrQResync(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	for _, tc := range []struct {
		enable                 string
		wantModSeq, wantVanish bool
	}{
		{"IMAP4rev2", false, false},
		{"IMAP4rev2 QRESYNC", true, true},
	} {
		t.Run(tc.enable, func(t *testing.T) {
			c := dialRawIMAP(t, server.Address)
			c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
			c.do("ENABLE " + tc.enable)
			mbox := "Rev2-" + strings.ReplaceAll(tc.enable, " ", "-")
			c.do("CREATE " + mbox)
			c.appendMsg(mbox, "Subject: rev2\r\n\r\nbody\r\n")
			c.do("SELECT " + mbox)

			untagged, _ := c.do(`STORE 1 +FLAGS (\Deleted)`)
			store := strings.Join(untagged, "\n")
			if got := strings.Contains(store, "MODSEQ"); got != tc.wantModSeq {
				t.Errorf("STORE: MODSEQ sent = %v, want %v:\n%s", got, tc.wantModSeq, store)
			}

			untagged, _ = c.do("EXPUNGE")
			expunge := strings.Join(untagged, "\n")
			gotVanish := strings.Contains(expunge, "* VANISHED")
			gotExpunge := strings.Contains(expunge, "* 1 EXPUNGE")
			if gotVanish != tc.wantVanish || gotExpunge == tc.wantVanish {
				t.Errorf("EXPUNGE: VANISHED %v, EXPUNGE %v; want VANISHED %v:\n%s", gotVanish, gotExpunge, tc.wantVanish, expunge)
			}
		})
	}
}
