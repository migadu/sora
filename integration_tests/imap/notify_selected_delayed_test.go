//go:build integration

package imap_test

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
	imapsrv "github.com/migadu/sora/server/imap"
)

// RFC 5465 §6.1.2: "The SELECTED-DELAYED mailbox specifier requires the server
// to delay a MessageExpunge event until the client issues a command that allows
// returning information about expunged messages (see Section 7.4.1 of [RFC3501]
// for more details), for example, till a NOOP or an IDLE command has been
// issued." RFC 3501 §7.4.1: "An EXPUNGE response MUST NOT be sent when no
// command is in progress" (#1495).

// TestNotifySelectedDelayedHoldsExpungeBetweenCommands: another connection's
// expunge is not sent while the watching connection has no command in
// progress, neither when a new message arrives behind it nor when the watching
// connection appended one itself just before. It comes with the next NOOP, and
// the new message's MessageNew FETCH comes after its EXISTS.
func TestNotifySelectedDelayedHoldsExpungeBetweenCommands(t *testing.T) {
	// A slow pump, so that its first tick sees the expunge and the new message
	// together: everything below happens well within one interval.
	const interval = 2 * time.Second
	imapsrv.SetNotifyPollIntervalForTests(interval)
	t.Cleanup(func() { imapsrv.SetNotifyPollIntervalForTests(notifyTestPollInterval) })

	for _, tc := range []struct {
		name string
		// own is whether the watching connection appends the new message
		// itself, before the expunge; otherwise the other connection appends
		// it after the expunge.
		own bool
	}{
		{name: "message from another connection"},
		{name: "own APPEND", own: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, account := common.SetupIMAPServer(t)
			defer server.Close()
			login := fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password)

			watcher := dialRawIMAP(t, server.Address)
			watcher.do(login)
			expungedUID := watcher.appendMsg("INBOX", notifyTestMessage)
			watcher.appendMsg("INBOX", notifyTestMessage)
			watcher.do("SELECT INBOX")

			other := dialRawIMAP(t, server.Address)
			other.do(login)
			other.do("SELECT INBOX")

			watcher.do("NOTIFY SET (SELECTED-DELAYED (MessageNew (UID) MessageExpunge))")

			var newUID imap.UID
			if tc.own {
				newUID = watcher.appendMsg("INBOX", notifyTestMessage)
			}
			other.do(fmt.Sprintf(`UID STORE %d +FLAGS.SILENT (\Deleted)`, expungedUID))
			other.do("EXPUNGE")
			if !tc.own {
				newUID = other.appendMsg("INBOX", notifyTestMessage)
			}

			// Two ticks with no command in progress: nothing may arrive.
			if got := readNotifyFor(t, watcher, 2*interval+interval/2); len(got) != 0 {
				t.Fatalf("SELECTED-DELAYED with no command in progress, want no response, got:\n%s", strings.Join(got, "\r\n"))
			}

			got := notifyNoop(t, watcher)
			if !tc.own && countUIDFetches(got, newUID) == 0 {
				got = append(got, readNotifyUntil(t, watcher, 3*interval, func(resps []string) bool {
					return countUIDFetches(resps, newUID) > 0
				})...)
			}

			expunge := slices.Index(got, "* 1 EXPUNGE")
			if expunge < 0 {
				t.Fatalf("want the delayed EXPUNGE with NOOP, got:\n%s", strings.Join(got, "\r\n"))
			}
			if tc.own {
				if n := countUIDFetches(got, newUID); n != 0 {
					t.Errorf("UID %d was appended on this connection, want no MessageNew FETCH for it, got %d:\n%s", newUID, n, strings.Join(got, "\r\n"))
				}
				return
			}
			exists := slices.Index(got, "* 2 EXISTS")
			fetch := slices.IndexFunc(got, func(resp string) bool { return countUIDFetches([]string{resp}, newUID) > 0 })
			if exists < expunge || fetch < exists {
				t.Errorf("want EXPUNGE, then EXISTS, then the MessageNew FETCH, got:\n%s", strings.Join(got, "\r\n"))
			}
			if want := fmt.Sprintf("* 2 FETCH (UID %d)", newUID); got[fetch] != want {
				t.Errorf("MessageNew FETCH = %q, want %q", got[fetch], want)
			}
			if n := countUIDFetches(got, newUID); n != 1 {
				t.Errorf("want one MessageNew FETCH for UID %d, got %d:\n%s", newUID, n, strings.Join(got, "\r\n"))
			}
		})
	}
}

// readNotifyFor returns the lines a NOTIFY session is sent within d while it
// issues no command.
func readNotifyFor(t *testing.T, c *rawIMAP, d time.Duration) []string {
	t.Helper()
	if err := c.conn.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	defer func() {
		if err := c.conn.SetReadDeadline(time.Time{}); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
	}()
	var lines []string
	for {
		line, err := c.r.ReadString('\n')
		if line != "" {
			lines = append(lines, strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return lines
			}
			t.Fatalf("read: %v, got:\n%s", err, strings.Join(lines, "\r\n"))
		}
	}
}
