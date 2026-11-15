//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestNotifyMessageNewFetchModSeqForCondStoreAwareClient: the FETCH that a
// MessageNew watch sends for a new message in the selected mailbox is "an
// unsolicited FETCH response containing the information requested by the
// client" (RFC 5465 §5.2), not the answer to a FETCH command. RFC 7162 §3.1:
// once the client is CONDSTORE-aware, "The server MUST then include
// mod-sequence data in all subsequent untagged FETCH responses (until the
// connection is closed)", and §3.2.4 asks "both UID and mod-sequence data" of a
// QRESYNC server. So MODSEQ is due even when the fetch-atts leave it out, and
// still not due to a client that never enabled CONDSTORE.
func TestNotifyMessageNewFetchModSeqForCondStoreAwareClient(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	const msg = "From: a@example.com\r\nTo: b@example.com\r\nSubject: notify modseq\r\n\r\nhello\r\n"
	for _, tc := range []struct {
		name       string
		setup      []string
		afterWatch []string
		wantModSeq bool
	}{
		{name: "SELECT CONDSTORE", setup: []string{"SELECT INBOX (CONDSTORE)"}, wantModSeq: true},
		{name: "ENABLE CONDSTORE", setup: []string{"ENABLE CONDSTORE", "SELECT INBOX"}, wantModSeq: true},
		{name: "ENABLE QRESYNC", setup: []string{"ENABLE QRESYNC", "SELECT INBOX"}, wantModSeq: true},
		// A FETCH with MODSEQ issued after NOTIFY SET enables CONDSTORE too.
		{name: "FETCH MODSEQ after NOTIFY", setup: []string{"SELECT INBOX"}, afterWatch: []string{"FETCH 1 (MODSEQ)"}, wantModSeq: true},
		{name: "not CONDSTORE-aware", setup: []string{"SELECT INBOX"}, wantModSeq: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, account := common.SetupIMAPServer(t)
			t.Cleanup(server.Close)
			login := fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)

			watcher := dialRawIMAP(t, server.Address)
			watcher.do(login)
			watcher.appendMsg("INBOX", msg)
			for _, cmd := range tc.setup {
				watcher.do(cmd)
			}
			watcher.do("NOTIFY SET (SELECTED (MessageNew (UID) MessageExpunge))")
			for _, cmd := range tc.afterWatch {
				watcher.do(cmd)
			}

			other := dialRawIMAP(t, server.Address)
			other.do(login)
			uid := other.appendMsg("INBOX", msg)

			if err := watcher.conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			var fetch string
			for fetch == "" {
				line, err := watcher.r.ReadString('\n')
				if err != nil {
					t.Fatalf("waiting for the MessageNew FETCH: %v", err)
				}
				if strings.HasPrefix(line, "* 2 FETCH ") {
					fetch = strings.TrimRight(line, "\r\n")
				}
			}
			if !strings.Contains(fetch, fmt.Sprintf("UID %d", uid)) {
				t.Errorf("MessageNew FETCH: want UID %d, got: %s", uid, fetch)
			}
			if got := strings.Contains(fetch, "MODSEQ ("); got != tc.wantModSeq {
				t.Errorf("MessageNew FETCH: MODSEQ present = %v, want %v; got: %s", got, tc.wantModSeq, fetch)
			}
			if err := watcher.conn.SetReadDeadline(time.Time{}); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			watcher.do("NOOP")
		})
	}
}
