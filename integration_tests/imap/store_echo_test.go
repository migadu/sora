//go:build integration

package imap_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// fetchLinesWithUID returns the FETCH responses for uid, wherever UID sits in
// the attribute list (fetchLinesForUID needs a trailing space, which a FETCH
// ending in "UID n)" does not have).
func fetchLinesWithUID(lines []string, uid int) []string {
	re := regexp.MustCompile(fmt.Sprintf(`^\* \d+ FETCH \(.*\bUID %d\b`, uid))
	var out []string
	for _, line := range lines {
		if re.MatchString(line) {
			out = append(out, line)
		}
	}
	return out
}

// requireStoreAnsweredOnce asserts that a non-silent STORE reported message
// uid exactly once, with its flags, and that the command-boundary poll did not
// report the same change again, neither in the STORE response nor at the next
// NOOP (RFC 9051 §6.4.6: STORE returns the updated value in an untagged FETCH).
func requireStoreAnsweredOnce(t *testing.T, c *rawIMAP, command string, uid int, condStore bool, want ...string) {
	t.Helper()
	lines, _ := c.do(command)
	fetches := fetchLinesWithUID(lines, uid)
	require.Len(t, fetches, 1, "%s: one FETCH per changed message: %q", command, lines)
	require.Contains(t, fetches[0], "FLAGS (", command)
	for _, flag := range want {
		require.Contains(t, fetches[0], flag, command)
	}
	if condStore {
		require.Contains(t, fetches[0], "MODSEQ (", command)
	} else {
		require.NotContains(t, fetches[0], "MODSEQ", command)
	}

	lines, _ = c.do("NOOP")
	require.Empty(t, fetchLinesWithUID(lines, uid), "%s: own change echoed by the next poll: %q", command, lines)
}

// A non-silent STORE answers every message it changed; the post-command poll
// must not report the same change a second time, while changes made by other
// sessions are still reported to this one and this session's changes to them.
func TestIMAP_StoreReportsOwnChangeOnce(t *testing.T) {
	for name, condStore := range map[string]bool{"plain": false, "condstore": true} {
		t.Run(name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()

			c := dialRawIMAP(t, server.Address)
			c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			c.appendMsg("INBOX", "Subject: echo\r\n\r\nbody\r\n")
			if condStore {
				c.do("ENABLE CONDSTORE")
			}
			c.do("SELECT INBOX")

			other := dialRawIMAP(t, server.Address)
			other.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			other.do("SELECT INBOX")

			for _, step := range []struct {
				command string
				want    []string
			}{
				{`STORE 1 +FLAGS (\Flagged)`, []string{`\Flagged`}},
				{`UID STORE 1 -FLAGS (\Flagged)`, nil},
				{`STORE 1 FLAGS (\Seen)`, []string{`\Seen`}},
				{`UID STORE 1 +FLAGS (Work)`, []string{`\Seen`, `Work`}},
			} {
				requireStoreAnsweredOnce(t, c, step.command, 1, condStore, step.want...)

				lines, _ := other.do("NOOP")
				require.Len(t, fetchLinesWithUID(lines, 1), 1, "%s: other session must be notified: %q", step.command, lines)
			}

			// A change by another session not yet reported here, then this
			// session's STORE on the same message: the STORE response carries
			// both, and nothing is reported again.
			other.do(`UID STORE 1 +FLAGS.SILENT (\Answered)`)
			requireStoreAnsweredOnce(t, c, `UID STORE 1 +FLAGS (\Flagged)`, 1, condStore, `\Answered`, `\Flagged`)

			// Same, with a STORE that changes nothing: its response reports the
			// other session's change, which the poll must not repeat.
			other.do(`UID STORE 1 -FLAGS.SILENT (\Answered)`)
			requireStoreAnsweredOnce(t, c, `UID STORE 1 +FLAGS (\Flagged)`, 1, condStore, `\Flagged`)

			// A change by another session after this session's STORE is
			// still reported.
			other.do(`UID STORE 1 +FLAGS.SILENT (\Deleted)`)
			lines, _ := c.do("NOOP")
			fetches := fetchLinesWithUID(lines, 1)
			require.Len(t, fetches, 1, "%q", lines)
			require.Contains(t, fetches[0], `\Deleted`)
		})
	}
}

// A sequence-number STORE cannot report EXPUNGE, so its poll stops at a pending
// expunge and leaves the rest queued for the next command. The STORE's own
// change must not be among what that next command reports.
func TestIMAP_StoreOwnChangeNotEchoedAfterPendingExpunge(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	for range 3 {
		c.appendMsg("INBOX", "Subject: pending expunge\r\n\r\nbody\r\n")
	}
	c.do("SELECT INBOX")

	other := dialRawIMAP(t, server.Address)
	other.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	other.do("SELECT INBOX")
	other.do(`UID STORE 3 +FLAGS.SILENT (\Deleted)`)
	other.do("EXPUNGE")

	command := `STORE 1 +FLAGS (\Flagged)`
	lines, _ := c.do(command)
	require.NotContains(t, strings.Join(lines, "\n"), "EXPUNGE", "sequence STORE must not report EXPUNGE: %q", lines)
	fetches := fetchLinesWithUID(lines, 1)
	require.Len(t, fetches, 1, "%s: %q", command, lines)
	require.Contains(t, fetches[0], `\Flagged`)

	lines, _ = c.do("NOOP")
	require.Contains(t, strings.Join(lines, "\n"), "* 3 EXPUNGE")
	require.Empty(t, fetchLinesWithUID(lines, 1), "own change echoed after the pending expunge: %q", lines)
}

// Under a NOTIFY watch with FlagChange the pump polls concurrently with the
// command; it must not report the STORE's own change either, whether its tick
// lands during the STORE or after it, while a change by another session still
// reaches this one.
func TestIMAP_StoreOwnChangeNotEchoedByNotify(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	c.appendMsg("INBOX", "Subject: notify echo\r\n\r\nbody\r\n")
	c.do("SELECT INBOX")
	c.do("NOTIFY SET (SELECTED (MessageNew MessageExpunge FlagChange))")

	for _, command := range []string{
		`STORE 1 +FLAGS (\Flagged)`,
		`UID STORE 1 -FLAGS (\Flagged)`,
		`UID STORE 1 +FLAGS (\Seen)`,
	} {
		lines, _ := c.do(command)
		require.Len(t, fetchLinesWithUID(lines, 1), 1, "%s: %q", command, lines)

		time.Sleep(time.Second) // several NOTIFY ticks (300ms in this package)
		lines, _ = c.do("NOOP")
		require.Empty(t, fetchLinesWithUID(lines, 1), "%s: own change echoed by the NOTIFY pump: %q", command, lines)
	}

	other := dialRawIMAP(t, server.Address)
	other.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	other.do("SELECT INBOX")
	other.do(`UID STORE 1 +FLAGS.SILENT (\Answered)`)
	time.Sleep(time.Second)
	lines, _ := c.do("NOOP")
	fetches := fetchLinesWithUID(lines, 1)
	require.Len(t, fetches, 1, "%q", lines)
	require.Contains(t, fetches[0], `\Answered`)
}
