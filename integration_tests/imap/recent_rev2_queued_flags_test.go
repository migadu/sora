//go:build integration

package imap_test

import (
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestIMAP_QueuedRecentFlagsRespectRev2Enable(t *testing.T) {
	for _, mode := range []string{"enable_after_queue", "rev1_control", "enable_before_queue_control"} {
		t.Run(mode, func(t *testing.T) {
			srv, account := common.SetupIMAPServer(t)
			defer srv.Close()
			foreign := dialRaw(t, srv.Address)
			defer foreign.conn.Close()
			watcher := dialRaw(t, srv.Address)
			defer watcher.conn.Close()
			require.NoError(t, foreign.conn.SetDeadline(time.Now().Add(20*time.Second)))
			require.NoError(t, watcher.conn.SetDeadline(time.Now().Add(20*time.Second)))
			foreign.login(account)
			watcher.login(account)
			cmd := func(c *rawConn, who, tag, line string) []string {
				t.Helper()
				t.Logf("%s C: %s %s", who, tag, line)
				lines, done := c.cmd(tag, line)
				for _, l := range lines {
					t.Logf("%s S: %s", who, l)
				}
				t.Logf("%s S: %s", who, done)
				require.Contains(t, done, tag+" OK")
				return lines
			}
			foreign.append("ap1", "INBOX", msg(1))
			foreign.append("ap2", "INBOX", msg(2))
			sel := cmd(watcher, "watcher", "wsel", "SELECT INBOX")
			require.Contains(t, sel, "* 2 RECENT", "watcher must own both recent messages in rev1")
			cmd(foreign, "foreign", "fsel", "SELECT INBOX")
			if mode == "enable_before_queue_control" {
				require.Contains(t, cmd(watcher, "watcher", "wpre", "ENABLE IMAP4rev2"), "* ENABLED IMAP4rev2")
			}
			cmd(foreign, "foreign", "fdel", `UID STORE 1 +FLAGS.SILENT (\Deleted)`)
			cmd(foreign, "foreign", "fexp", "EXPUNGE")
			cmd(foreign, "foreign", "fflag", `UID STORE 2 +FLAGS.SILENT (\Flagged)`)
			held := cmd(watcher, "watcher", "whold", "FETCH 2 (UID)")
			require.Empty(t, expungeSeqs(held), "FETCH is expunge-unsafe and must leave the earlier EXPUNGE queued")
			for _, l := range held {
				require.NotContains(t, l, "FLAGS (", "the flag update behind EXPUNGE must still be queued")
			}
			release := "NOOP"
			if mode == "enable_after_queue" {
				release = "ENABLE IMAP4rev2"
			}
			out := cmd(watcher, "watcher", "wrelease", release)
			require.Equal(t, []string{"1"}, expungeSeqs(out), "the held EXPUNGE must now be flushed")
			var queued string
			for _, l := range out {
				if strings.Contains(l, "FETCH (") && strings.Contains(l, "FLAGS (") {
					queued = l
				}
			}
			require.NotEmpty(t, queued, "proof must flush a real queued FLAGS response")
			require.Contains(t, queued, `\Flagged`)
			if mode == "rev1_control" {
				require.Contains(t, queued, `\Recent`)
			} else {
				if mode == "enable_after_queue" {
					require.Contains(t, out, "* ENABLED IMAP4rev2")
				}
				if strings.Contains(strings.ToLower(queued), `\recent`) {
					t.Errorf("queued FLAGS retained obsolete Recent after rev2 activation: %s", queued)
				}
			}
			direct := cmd(watcher, "watcher", "wfresh", "UID FETCH 2 (FLAGS)")
			require.NotEmpty(t, direct)
			if mode != "rev1_control" {
				for _, l := range direct {
					require.NotContains(t, strings.ToLower(l), `\recent`, "fresh rev2 FETCH must omit Recent")
				}
			}
		})
	}
}
