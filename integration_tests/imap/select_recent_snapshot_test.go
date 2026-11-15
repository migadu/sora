//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var selectRecentRe = regexp.MustCompile(`^\* (\d+) RECENT$`)

// TestIMAP_SelectCountsRecentInItsSnapshot is the regression test for #1361: SELECT took
// EXISTS from the mailbox summary, then counted RECENT in a later statement against the
// live mailbox. A delivery that committed in between was counted by RECENT but not by
// EXISTS, and an expunge in between was left out of RECENT while EXISTS still counted
// the message.
//
// The server has seen a read-write SELECT of INBOX with UIDs 1-4, so only messages
// above UID 4 are recent. The next SELECT is paused just after the summary while
// another session writes; its RECENT must count the messages above UID 4 that its
// EXISTS counts.
func TestIMAP_SelectCountsRecentInItsSnapshot(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	msg := func(n int) string {
		return fmt.Sprintf("From: sender@example.com\r\nTo: user@example.com\r\nSubject: recent %d\r\n\r\nbody %d\r\n", n, n)
	}

	cases := []struct {
		name string
		// reselect: the SELECT reselects the mailbox the session itself selected last.
		// Otherwise another session on the server selected it, and the SELECT counts
		// from the server-wide baseline.
		reselect bool
		before   func(w *rawIMAP) // commits before the SELECT
		write    func(w *rawIMAP) // commits while the SELECT is paused after its summary
		// The mailbox at the summary: EXISTS and the messages above UID 4.
		wantExists, wantRecent int
	}{
		{
			name:       "delivery after the summary",
			write:      func(w *rawIMAP) { w.appendMsg("INBOX", msg(5)) },
			wantExists: 4, wantRecent: 0,
		},
		{
			name:       "delivery after the summary on reselect",
			reselect:   true,
			write:      func(w *rawIMAP) { w.appendMsg("INBOX", msg(5)) },
			wantExists: 4, wantRecent: 0,
		},
		{
			name: "expunge of a recent message after the summary",
			before: func(w *rawIMAP) {
				w.appendMsg("INBOX", msg(5))
				w.appendMsg("INBOX", msg(6))
			},
			write: func(w *rawIMAP) {
				w.do(`UID STORE 6 +FLAGS.SILENT (\Deleted)`)
				w.do("UID EXPUNGE 6")
			},
			wantExists: 6, wantRecent: 2,
		},
		{
			name:     "expunge of a recent message after the summary on reselect",
			reselect: true,
			before: func(w *rawIMAP) {
				w.appendMsg("INBOX", msg(5))
				w.appendMsg("INBOX", msg(6))
			},
			write: func(w *rawIMAP) {
				w.do(`UID STORE 6 +FLAGS.SILENT (\Deleted)`)
				w.do("UID EXPUNGE 6")
			},
			wantExists: 6, wantRecent: 2,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()

			// The writer works on another server, so its own SELECT does not move the
			// traced server's Recent baseline.
			w := dialRawIMAP(t, server.Address)
			w.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			for i := 1; i <= 4; i++ {
				w.appendMsg("INBOX", msg(i))
			}
			w.do("SELECT INBOX")

			ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(ctx, owner.Email)
			require.NoError(t, err)
			mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, ownerID, "INBOX")
			require.NoError(t, err)

			gate := &selectSummaryGate{mailboxID: mailbox.ID, reached: make(chan struct{}), release: make(chan struct{})}
			defer gate.resume()
			addr := startTracedIMAPServer(t, server.ResilientDB, gate)

			// A read-write SELECT of UIDs 1-4 on the traced server.
			first := dialRawIMAP(t, addr)
			first.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			first.do("SELECT INBOX")

			c := first
			if !tc.reselect {
				c = dialRawIMAP(t, addr)
				c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			}
			if tc.before != nil {
				tc.before(w)
			}

			gate.armed.Store(true)
			done := make(chan []string, 1)
			go func() {
				untagged, _ := c.do("SELECT INBOX")
				done <- untagged
			}()
			select {
			case <-gate.reached:
			case <-time.After(5 * time.Second):
				t.Fatal("SELECT did not reach the summary gate")
			}
			tc.write(w)
			gate.resume()

			var lines []string
			select {
			case lines = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("SELECT did not finish")
			}
			t.Logf("SELECT response:\n%s", strings.Join(lines, "\n"))

			// The SELECT's own EXISTS and RECENT come first.
			exists, ok := qrsNumber(t, qrsExistsRe, lines)
			require.True(t, ok, "no EXISTS in the SELECT response")
			recent, ok := qrsNumber(t, selectRecentRe, lines)
			require.True(t, ok, "no RECENT in the SELECT response")
			require.Equalf(t, tc.wantExists, int(exists), "harness broken: the SELECT did not read its summary before the write")
			assert.Equalf(t, tc.wantRecent, int(recent),
				"* %d EXISTS, * %d RECENT: RECENT must count the messages above UID 4 among the %d that EXISTS counts",
				exists, recent, exists)

			// The next poll announces what happened after the summary. UID 5 is
			// \Recent in this session, as SEARCH RECENT answers from the baseline the
			// SELECT counted from.
			c.do("NOOP")
			searchRecent, _ := c.do("UID SEARCH RECENT")
			assert.Equal(t, "5", responseNums(searchRecent, "* SEARCH"), "UID SEARCH RECENT after the poll")
		})
	}
}
