//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func fetchLinesForUID(lines []string, uid int) []string {
	var out []string
	for _, line := range lines {
		if strings.Contains(line, " FETCH ") && strings.Contains(line, fmt.Sprintf("UID %d ", uid)) {
			out = append(out, line)
		}
	}
	return out
}

// requireSilentModSeqOnly asserts the RFC 7162 §3.1.3 response to a .SILENT
// STORE from a CONDSTORE-aware client: exactly one FETCH for the message,
// carrying MODSEQ and no FLAGS.
func requireSilentModSeqOnly(t *testing.T, lines []string, uid int, command string) {
	t.Helper()
	fetches := fetchLinesForUID(lines, uid)
	require.Len(t, fetches, 1, "%s: %q", command, lines)
	require.Contains(t, fetches[0], "MODSEQ (", command)
	require.NotContains(t, fetches[0], "FLAGS (", "%s: .SILENT must not return the flags", command)
}

// A .SILENT STORE that changes a message must answer with MODSEQ only; the
// flags must not come back through the command-boundary poll either, while
// other sessions on the mailbox still learn the new flags.
func TestIMAP_StoreSilentModifiedRowDoesNotLeakFlags(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	c.appendMsg("INBOX", "Subject: silent\r\n\r\nbody\r\n")
	c.do("SELECT INBOX (CONDSTORE)")

	other := dialRawIMAP(t, server.Address)
	other.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	other.do("SELECT INBOX (CONDSTORE)")

	for _, command := range []string{
		`UID STORE 1 +FLAGS.SILENT (\Seen)`,
		`UID STORE 1 -FLAGS.SILENT (\Seen)`,
		`UID STORE 1 FLAGS.SILENT (\Flagged)`,
		`STORE 1 +FLAGS.SILENT (\Answered)`,
	} {
		lines, _ := c.do(command)
		requireSilentModSeqOnly(t, lines, 1, command)

		lines, _ = c.do("NOOP")
		require.Empty(t, fetchLinesForUID(lines, 1), "%s: own silent change must not be echoed later: %q", command, lines)

		lines, _ = other.do("NOOP")
		fetches := fetchLinesForUID(lines, 1)
		require.Len(t, fetches, 1, "%s: other session must be notified: %q", command, lines)
		require.Contains(t, fetches[0], "FLAGS (")
		require.Contains(t, fetches[0], "MODSEQ (")
	}

	// A change made by another session is still reported to this one, flags included.
	other.do(`UID STORE 1 +FLAGS.SILENT (\Deleted)`)
	lines, _ := c.do("NOOP")
	fetches := fetchLinesForUID(lines, 1)
	require.Len(t, fetches, 1, "%q", lines)
	require.Contains(t, fetches[0], `\Deleted`)
}

// The MODSEQ response is command data, not a notification: a NOTIFY watch that
// leaves out FlagChange (or NOTIFY NONE) must not swallow it.
func TestIMAP_StoreSilentReturnsModSeqUnderNotify(t *testing.T) {
	for name, notify := range map[string]string{
		"none":         "NOTIFY NONE",
		"noflagchange": "NOTIFY SET (SELECTED (MessageNew MessageExpunge))",
	} {
		t.Run(name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()
			c := dialRawIMAP(t, server.Address)
			c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			c.appendMsg("INBOX", "Subject: notify\r\n\r\nbody\r\n")
			c.do("SELECT INBOX (CONDSTORE)")
			c.do(notify)
			for _, command := range []string{
				`UID STORE 1 +FLAGS.SILENT (\Seen)`,
				`UID STORE 1 -FLAGS.SILENT (\Seen)`,
			} {
				lines, _ := c.do(command)
				requireSilentModSeqOnly(t, lines, 1, command)
			}
		})
	}
}

// A sequence-number STORE cannot report EXPUNGE, so its poll stops at a pending
// expunge. The STORE's own MODSEQ response must not be stuck behind it.
func TestIMAP_StoreSilentReturnsModSeqWithPendingExpunge(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	for range 3 {
		c.appendMsg("INBOX", "Subject: pending expunge\r\n\r\nbody\r\n")
	}
	c.do("SELECT INBOX (CONDSTORE)")

	other := dialRawIMAP(t, server.Address)
	other.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	other.do("SELECT INBOX")
	other.do(`UID STORE 3 +FLAGS.SILENT (\Deleted)`)
	other.do("EXPUNGE")

	command := `STORE 1 +FLAGS.SILENT (\Seen)`
	lines, _ := c.do(command)
	for _, line := range lines {
		require.NotContains(t, line, "EXPUNGE", "sequence STORE must not report EXPUNGE: %q", lines)
		require.NotContains(t, line, "VANISHED", "sequence STORE must not report VANISHED: %q", lines)
	}
	requireSilentModSeqOnly(t, lines, 1, command)

	lines, _ = c.do("NOOP")
	require.Contains(t, strings.Join(lines, "\n"), "* 3 EXPUNGE")
	require.Empty(t, fetchLinesForUID(lines, 1), "own silent change must not be echoed later: %q", lines)
}

// RFC 4314 §4: STORE fails with NOPERM when the user may modify none of the
// flags. A replace touches every flag, so it can only succeed with at least
// one of the 's', 't' and 'w' rights.
func TestIMAP_StoreReplaceWithoutFlagRightsIsNoPerm(t *testing.T) {
	for _, rights := range []string{"lri", "lre"} {
		t.Run(rights, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()
			guestEmail, guestPassword := createSecondUser(t, server, "example.com", "store-noperm")
			o := dialRawIMAP(t, server.Address)
			o.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			o.do("CREATE Shared/NoFlagRights")
			o.do(fmt.Sprintf("SETACL Shared/NoFlagRights %s %s", guestEmail, rights))
			o.appendMsg("Shared/NoFlagRights", "Subject: noperm\r\n\r\nbody\r\n")
			o.do("SELECT Shared/NoFlagRights")
			o.do(`UID STORE 1 FLAGS (\Flagged)`)

			c := dialRawIMAP(t, server.Address)
			c.do(fmt.Sprintf("LOGIN %s %s", guestEmail, guestPassword))
			_, tagged := c.do("SELECT Shared/NoFlagRights")
			require.Contains(t, tagged, "READ-WRITE", "fixture: the mailbox must be selected read-write")

			require.Contains(t, c.status(`UID STORE 1 +FLAGS (\Seen)`), "NO [NOPERM]", "fixture: +FLAGS is refused")
			for _, command := range []string{
				`UID STORE 1 FLAGS (\Seen)`,
				`UID STORE 1 FLAGS ()`,
				`UID STORE 1 FLAGS.SILENT (\Seen Work)`,
				`STORE 1 FLAGS (\Seen)`,
			} {
				require.Contains(t, c.status(command), "NO [NOPERM]", command)
			}

			lines, _ := o.do("UID FETCH 1 FLAGS")
			flags := strings.Join(lines, " ")
			require.Contains(t, flags, `\Flagged`)
			require.NotContains(t, flags, `\Seen`)
		})
	}
}

// A replace by a user holding only some flag rights still succeeds (RFC 4314
// §4: do not fail when at least one flag can be modified).
func TestIMAP_StoreReplaceWithPartialFlagRightsSucceeds(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	guestEmail, guestPassword := createSecondUser(t, server, "example.com", "store-partial")
	o := dialRawIMAP(t, server.Address)
	o.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	o.do("CREATE Shared/SeenOnly")
	o.do(fmt.Sprintf("SETACL Shared/SeenOnly %s lrs", guestEmail))
	o.appendMsg("Shared/SeenOnly", "Subject: partial\r\n\r\nbody\r\n")

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", guestEmail, guestPassword))
	c.do("SELECT Shared/SeenOnly")
	require.Contains(t, c.status(`UID STORE 1 FLAGS (\Flagged)`), "OK")
	require.Contains(t, c.status(`UID STORE 1 FLAGS (\Seen)`), "OK")
}

// A .SILENT STORE answers MODSEQ only, which tells a CONDSTORE client nothing
// about a change another session made to the same message since this session
// last polled. That change must still be reported to this session, flags
// included, by the end of the STORE or at the next command (RFC 9051 §6.4.6
// Note: "Regardless of whether or not the ".SILENT" suffix was used, the server
// SHOULD send an untagged FETCH response if a change to a message's flags from
// an external source is observed."). Otherwise the client caches the MODSEQ
// with flags that lack the other session's change, and a later CHANGEDSINCE
// resync never repairs it.
func TestIMAP_StoreSilentReportsOtherSessionChange(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	c.appendMsg("INBOX", "Subject: silent external\r\n\r\nbody\r\n")
	c.do("SELECT INBOX (CONDSTORE)")

	other := dialRawIMAP(t, server.Address)
	other.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	other.do("SELECT INBOX")

	for _, step := range []struct {
		external string
		command  string
		want     []string
		notWant  []string
	}{
		{`UID STORE 1 +FLAGS.SILENT (\Answered)`, `UID STORE 1 +FLAGS.SILENT (\Seen)`, []string{`\Answered`, `\Seen`}, nil},
		{`UID STORE 1 +FLAGS.SILENT (\Flagged)`, `STORE 1 -FLAGS.SILENT (\Seen)`, []string{`\Answered`, `\Flagged`}, []string{`\Seen`}},
		{`UID STORE 1 -FLAGS.SILENT (\Answered)`, `UID STORE 1 (UNCHANGEDSINCE 9223372036854775807) +FLAGS.SILENT (Work)`, []string{`\Flagged`, `Work`}, []string{`\Answered`}},
	} {
		other.do(step.external)

		storeLines, _ := c.do(step.command)
		answered := false
		for _, line := range fetchLinesWithUID(storeLines, 1) {
			if !strings.Contains(line, "FLAGS (") {
				require.Contains(t, line, "MODSEQ (", step.command)
				answered = true
			}
		}
		require.True(t, answered, "%s: the MODSEQ answer is missing: %q", step.command, storeLines)

		noopLines, _ := c.do("NOOP")
		var reports []string
		for _, line := range fetchLinesWithUID(append(storeLines, noopLines...), 1) {
			if strings.Contains(line, "FLAGS (") {
				reports = append(reports, line)
			}
		}
		require.Len(t, reports, 1, "%s after %s: the other session's change must be reported once: STORE %q, NOOP %q",
			step.command, step.external, storeLines, noopLines)
		require.Contains(t, reports[0], "MODSEQ (", step.command)
		for _, flag := range step.want {
			require.Contains(t, reports[0], flag, step.command)
		}
		for _, flag := range step.notWant {
			require.NotContains(t, reports[0], flag, step.command)
		}

		lines, _ := c.do("NOOP")
		require.Empty(t, fetchLinesWithUID(lines, 1), "%s: reported again: %q", step.command, lines)
	}

	// With nothing changed elsewhere in between, the session's own .SILENT
	// change is still not echoed (TestIMAP_StoreSilentModifiedRowDoesNotLeakFlags).
	lines, _ := c.do(`UID STORE 1 +FLAGS.SILENT (\Seen)`)
	requireSilentModSeqOnly(t, lines, 1, `UID STORE 1 +FLAGS.SILENT (\Seen)`)
	lines, _ = c.do("NOOP")
	require.Empty(t, fetchLinesWithUID(lines, 1), "own silent change echoed: %q", lines)
}

// Under NOTIFY NONE no poll runs between commands, so a second .SILENT STORE
// on a message finds it at the first one's mod-sequence, above the poll
// cursor. The client has that state (the first STORE answered it), so neither
// change is reported once polling resumes; a change by another session in
// between still is.
func TestIMAP_StoreSilentRepeatedWithoutPoll(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	c.appendMsg("INBOX", "Subject: silent repeated\r\n\r\nbody\r\n")
	c.do("SELECT INBOX (CONDSTORE)")

	other := dialRawIMAP(t, server.Address)
	other.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	other.do("SELECT INBOX")

	resumeAndPoll := func(c *rawIMAP) []string {
		lines, _ := c.do("NOTIFY SET (SELECTED (MessageNew MessageExpunge FlagChange))")
		noop, _ := c.do("NOOP")
		return append(lines, noop...)
	}
	c.do("NOTIFY NONE")
	for _, command := range []string{`UID STORE 1 +FLAGS.SILENT (\Seen)`, `UID STORE 1 +FLAGS.SILENT (\Flagged)`} {
		lines, _ := c.do(command)
		requireSilentModSeqOnly(t, lines, 1, command)
	}
	lines := resumeAndPoll(c)
	require.Empty(t, fetchLinesWithUID(lines, 1), "own silent changes echoed: %q", lines)

	c.do("NOTIFY NONE")
	c.do(`UID STORE 1 +FLAGS.SILENT (Work)`)
	other.do(`UID STORE 1 +FLAGS.SILENT (\Answered)`)
	c.do(`UID STORE 1 -FLAGS.SILENT (\Seen)`)
	lines = resumeAndPoll(c)
	fetches := fetchLinesWithUID(lines, 1)
	require.Len(t, fetches, 1, "the other session's change must be reported: %q", lines)
	for _, flag := range []string{"FLAGS (", `\Answered`, `\Flagged`, "Work", "MODSEQ ("} {
		require.Contains(t, fetches[0], flag)
	}
	require.NotContains(t, fetches[0], `\Seen`)
}
