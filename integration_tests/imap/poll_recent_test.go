//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pollRecent returns the EXISTS and RECENT counts in lines, and whether the
// RECENT came after the EXISTS; -1 for a response that is not there.
func pollRecent(lines []string) (exists, recent int, recentAfterExists bool) {
	exists, recent = -1, -1
	existsAt, recentAt := -1, -1
	for i, l := range lines {
		if m := qrsExistsRe.FindStringSubmatch(l); m != nil {
			exists, _ = strconv.Atoi(m[1])
			existsAt = i
		}
		if m := selectRecentRe.FindStringSubmatch(l); m != nil {
			recent, _ = strconv.Atoi(m[1])
			recentAt = i
		}
	}
	return exists, recent, existsAt >= 0 && recentAt > existsAt
}

func pollRecentMsg(n int) string {
	return fmt.Sprintf("From: sender@example.com\r\nTo: user@example.com\r\nSubject: poll recent %d\r\n\r\nbody %d\r\n", n, n)
}

// TestIMAP_PollAnnouncesRecent is the regression test for #1474: a poll that
// announced new messages to an IMAP4rev1 session sent "* n EXISTS" but no
// "* n RECENT", so the client kept the RECENT count of its SELECT although
// SEARCH RECENT found the new messages. RFC 3501 §7.3.2: the RECENT response
// "occurs as a result of a SELECT or EXAMINE command, and if the size of the
// mailbox changes (e.g., new messages)".
func TestIMAP_PollAnnouncesRecent(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	login := func() *rawIMAP {
		c := dialRawIMAP(t, server.Address)
		c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
		return c
	}

	// UIDs 1-4, which a read-write SELECT on this server has already seen.
	w := login()
	for i := 1; i <= 4; i++ {
		w.appendMsg("INBOX", pollRecentMsg(i))
	}
	w.do("SELECT INBOX")

	c := login()
	lines, _ := c.do("SELECT INBOX")
	exists, recent, _ := pollRecent(lines)
	require.Equal(t, 4, exists, "SELECT: %q", lines)
	require.Equal(t, 0, recent, "harness: UIDs 1-4 were seen by an earlier read-write SELECT: %q", lines)

	// A delivery: the poll grows the mailbox to 5, and UID 5 is \Recent here.
	w.appendMsg("INBOX", pollRecentMsg(5))
	lines, _ = c.do("NOOP")
	exists, recent, after := pollRecent(lines)
	require.Equal(t, 5, exists, "NOOP: %q", lines)
	assert.Equal(t, 1, recent, "NOOP announcing UID 5 must report * 1 RECENT: %q", lines)
	assert.True(t, after, "RECENT must follow the EXISTS it counts: %q", lines)
	search, _ := c.do("UID SEARCH RECENT")
	assert.Equal(t, "5", responseNums(search, "* SEARCH"))

	// An expunge and a delivery while the client is in a FETCH, which may not be
	// sent an EXPUNGE (RFC 3501 §7.4.1). The EXISTS waits behind the EXPUNGE, and
	// so must the RECENT: both reach the client with the next NOOP.
	w.do(`UID STORE 1 +FLAGS.SILENT (\Deleted)`)
	w.do("UID EXPUNGE 1")
	w.appendMsg("INBOX", pollRecentMsg(6))
	lines, _ = c.do("FETCH 2 (FLAGS)")
	exists, recent, _ = pollRecent(lines)
	require.Equal(t, -1, exists, "harness: FETCH must hold the EXISTS back behind the EXPUNGE: %q", lines)
	assert.Equal(t, -1, recent, "FETCH: no RECENT for an EXISTS the client has not been sent: %q", lines)

	lines, _ = c.do("NOOP")
	require.True(t, slices.Contains(lines, "* 1 EXPUNGE"), "NOOP: %q", lines)
	exists, recent, after = pollRecent(lines)
	require.Equal(t, 5, exists, "NOOP: %q", lines)
	assert.Equal(t, 2, recent, "UIDs 5 and 6 are \\Recent: %q", lines)
	assert.True(t, after, "RECENT must follow the EXISTS it counts: %q", lines)
	search, _ = c.do("UID SEARCH RECENT")
	assert.Equal(t, "5 6", responseNums(search, "* SEARCH"))

	// A \Recent message is expunged and another one delivered: the count drops
	// the expunged one.
	w.do(`UID STORE 5 +FLAGS.SILENT (\Deleted)`)
	w.do("UID EXPUNGE 5")
	w.appendMsg("INBOX", pollRecentMsg(7))
	lines, _ = c.do("NOOP")
	require.True(t, slices.Contains(lines, "* 4 EXPUNGE"), "NOOP: %q", lines)
	exists, recent, after = pollRecent(lines)
	require.Equal(t, 5, exists, "NOOP: %q", lines)
	assert.Equal(t, 2, recent, "UIDs 6 and 7 are \\Recent, 5 is gone: %q", lines)
	assert.True(t, after, "RECENT must follow the EXISTS it counts: %q", lines)
	search, _ = c.do("UID SEARCH RECENT")
	assert.Equal(t, "6 7", responseNums(search, "* SEARCH"))

	// A poll that only expunges a message that is not \Recent sends no EXISTS
	// (RFC 3501 §7.4.1), and the RECENT count the client holds is still right.
	w.do(`UID STORE 2 +FLAGS.SILENT (\Deleted)`)
	w.do("UID EXPUNGE 2")
	lines, _ = c.do("NOOP")
	require.True(t, slices.Contains(lines, "* 1 EXPUNGE"), "NOOP: %q", lines)
	exists, recent, _ = pollRecent(lines)
	assert.Equal(t, -1, exists, "NOOP: %q", lines)
	assert.Equal(t, -1, recent, "NOOP: %q", lines)

	// An expunge of a \Recent message also changes the size of the mailbox, and
	// the client cannot tell from the EXPUNGE that the count dropped, so the
	// corrected count follows it. The client knows UIDs 3, 4, 6, 7.
	w.do(`UID STORE 6 +FLAGS.SILENT (\Deleted)`)
	w.do("UID EXPUNGE 6")
	lines, _ = c.do("NOOP")
	exists, recent, _ = pollRecent(lines)
	assert.Equal(t, -1, exists, "NOOP: %q", lines)
	assert.Equal(t, 1, recent, "UID 6 was \\Recent, 7 still is: %q", lines)
	assert.True(t, recentAfter(lines, "* 3 EXPUNGE"), "RECENT must follow the EXPUNGE it counts: %q", lines)
	search, _ = c.do("UID SEARCH RECENT")
	assert.Equal(t, "7", responseNums(search, "* SEARCH"))

	// The same during a FETCH: the EXPUNGE waits for the NOOP, and so does the
	// RECENT. The client knows UIDs 3, 4, 7.
	w.do(`UID STORE 7 +FLAGS.SILENT (\Deleted)`)
	w.do("UID EXPUNGE 7")
	lines, _ = c.do("FETCH 1 (FLAGS)")
	require.False(t, slices.Contains(lines, "* 3 EXPUNGE"), "harness: FETCH must hold the EXPUNGE back: %q", lines)
	_, recent, _ = pollRecent(lines)
	assert.Equal(t, -1, recent, "FETCH: no RECENT for an EXPUNGE the client has not been sent: %q", lines)
	lines, _ = c.do("NOOP")
	_, recent, _ = pollRecent(lines)
	assert.Equal(t, 0, recent, "no \\Recent message is left: %q", lines)
	assert.True(t, recentAfter(lines, "* 3 EXPUNGE"), "RECENT must follow the EXPUNGE it counts: %q", lines)
}

// recentAfter reports whether lines has a RECENT response after the line want.
func recentAfter(lines []string, want string) bool {
	at := slices.Index(lines, want)
	if at < 0 {
		return false
	}
	return slices.ContainsFunc(lines[at+1:], selectRecentRe.MatchString)
}

// TestIMAP_PollRecentLeavesOutMessagesSeenBeforeTheBaseline: the poll's RECENT
// counts the set SEARCH RECENT answers with, the messages above the baseline
// the SELECT read. A message another read-write session was notified of while
// the SELECT was between its summary and that baseline is in the mailbox the
// next poll announces, but it is not \Recent in this session: "if the session
// is read-write, subsequent sessions will not see \Recent set for this
// message" (RFC 3501 §2.3.2).
func TestIMAP_PollRecentLeavesOutMessagesSeenBeforeTheBaseline(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	// The writer works on another server, so its own SELECT does not move the
	// traced server's Recent baseline.
	w := dialRawIMAP(t, server.Address)
	w.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	for i := 1; i <= 4; i++ {
		w.appendMsg("INBOX", pollRecentMsg(i))
	}

	ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(ctx, owner.Email)
	require.NoError(t, err)
	mailbox, err := server.ResilientDB.GetMailboxByNameWithRetry(ctx, ownerID, "INBOX")
	require.NoError(t, err)
	gate := &selectSummaryGate{mailboxID: mailbox.ID, reached: make(chan struct{}), release: make(chan struct{})}
	defer gate.resume()
	addr := startTracedIMAPServer(t, server.ResilientDB, gate)
	login := func() *rawIMAP {
		c := dialRawIMAP(t, addr)
		c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
		return c
	}

	// A read-write session on the traced server: baseline UID 4.
	first := login()
	first.do("SELECT INBOX")

	c := login()
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
	// UID 5 arrives after the summary, and the first session is notified of it
	// first, which moves the server's baseline to UID 5.
	w.appendMsg("INBOX", pollRecentMsg(5))
	lines, _ := first.do("NOOP")
	require.Contains(t, lines, "* 5 EXISTS", "harness: the first session must be notified of UID 5")
	gate.resume()

	select {
	case lines = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("SELECT did not finish")
	}
	exists, recent, _ := pollRecent(lines)
	require.Equal(t, 4, exists, "harness: the SELECT did not read its summary before UID 5: %q", lines)
	require.Equal(t, 0, recent, "harness: the SELECT read its baseline after the first session's poll: %q", lines)

	lines, _ = c.do("NOOP")
	exists, recent, after := pollRecent(lines)
	require.Equal(t, 5, exists, "NOOP: %q", lines)
	assert.Equal(t, 0, recent, "UID 5 is not \\Recent in this session: %q", lines)
	assert.True(t, after, "RECENT must follow the EXISTS it counts: %q", lines)
	search, _ := c.do("UID SEARCH RECENT")
	assert.Empty(t, responseNums(search, "* SEARCH"))
}

// TestIMAP_PollSendsNoRecentToIMAP4rev2: IMAP4rev2 deprecates the RECENT
// response (RFC 9051 Appendix E, item 12), so a session that enabled it is sent
// only the EXISTS.
func TestIMAP_PollSendsNoRecentToIMAP4rev2(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	w := dialRawIMAP(t, server.Address)
	w.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	w.appendMsg("INBOX", pollRecentMsg(1))

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	lines, _ := c.do("ENABLE IMAP4rev2")
	require.True(t, slices.ContainsFunc(lines, func(l string) bool {
		return strings.HasPrefix(l, "* ENABLED") && strings.Contains(l, "IMAP4rev2")
	}), "ENABLE IMAP4rev2: %q", lines)
	c.do("SELECT INBOX")

	w.appendMsg("INBOX", pollRecentMsg(2))
	lines, _ = c.do("NOOP")
	exists, recent, _ := pollRecent(lines)
	require.Equal(t, 2, exists, "NOOP: %q", lines)
	assert.Equal(t, -1, recent, "an IMAP4rev2 session is sent no RECENT: %q", lines)
}
