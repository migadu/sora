//go:build integration

package imap_test

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// When an earlier Poll queued an older flag update behind a withheld EXPUNGE,
// a subsequent non-silent STORE writes its own FETCH (FLAGS ...) before those
// queued tracker updates are flushed. STORE must not suppress Poll's update via
// ownStoreEcho while SessionTracker holds queued updates; otherwise the older
// queued FLAGS response is flushed after STORE's answer and overwrites it.
func TestIMAP_StoreNotOvertakenByQueuedTrackerFlagUpdate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
	}{
		{"uid_store", `UID STORE 1 +FLAGS (\Seen)`},
		{"seq_store", `STORE 1 +FLAGS (\Seen)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()

			c := dialRawIMAP(t, server.Address)
			c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			for range 3 {
				c.appendMsg("INBOX", "Subject: store queued overtake\r\n\r\nbody\r\n")
			}
			c.do("SELECT INBOX")

			other := dialRawIMAP(t, server.Address)
			other.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			other.do("SELECT INBOX")
			other.do(`UID STORE 3 +FLAGS.SILENT (\Deleted)`)
			other.do("EXPUNGE")
			other.do(`UID STORE 1 +FLAGS.SILENT (\Answered)`)

			// Sequence FETCH runs Poll(allowExpunge=false), advancing the poll
			// cursor and queueing [Expunge(3), Fetch(1, FLAGS=(\Answered))] in
			// SessionTracker behind the withheld EXPUNGE.
			preLines, _ := c.do("FETCH 2 (UID)")
			for _, line := range preLines {
				require.NotContains(t, line, "EXPUNGE", "precondition: EXPUNGE must stay queued: %q", preLines)
			}
			require.Empty(t, fetchLinesWithUID(preLines, 1), "precondition: UID 1 flag update must stay queued: %q", preLines)

			storeLines, _ := c.do(tc.command)
			noopLines, _ := c.do("NOOP")
			combined := append(storeLines, noopLines...)

			require.Contains(t, strings.Join(combined, "\n"), "* 3 EXPUNGE",
				"%s: queued EXPUNGE must be delivered: STORE %q, NOOP %q", tc.command, storeLines, noopLines)

			var lastFlags string
			for _, line := range fetchLinesWithUID(combined, 1) {
				if strings.Contains(line, "FLAGS (") {
					lastFlags = line
				}
			}
			require.NotEmpty(t, lastFlags, "%s: no FLAGS reported for UID 1: STORE %q, NOOP %q", tc.command, storeLines, noopLines)
			require.Regexp(t, seenFlagsRe, lastFlags,
				"%s: stale queued FLAGS overtook STORE's \\Seen answer: STORE %q, NOOP %q", tc.command, storeLines, noopLines)
			require.Contains(t, lastFlags, `\Answered`,
				"%s: external \\Answered change missing from final FLAGS: STORE %q, NOOP %q", tc.command, storeLines, noopLines)

			afterLines, _ := c.do("NOOP")
			require.Empty(t, fetchLinesWithUID(afterLines, 1), "%s: echoed again after sync: %q", tc.command, afterLines)
		})
	}
}

// When SessionTracker holds an external flag update queued behind a withheld
// EXPUNGE, s.currentHighestModSeq has already advanced past that update even
// though the client has not received it yet. Under CONDSTORE, a .SILENT STORE
// on that message must not treat clientHasModSeqLocked as true or record its
// MODSEQ in ownStoreEcho: otherwise Store emits MODSEQ (M2) without FLAGS, and
// Poll suppresses M2 while flushing the older queued FLAGS (M1), leaving the
// client with stale FLAGS and a regressed MODSEQ (M1 < M2).
func TestIMAP_StoreSilentCondStoreQueuedTrackerDoesNotLoseFlagsOrRegressModSeq(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
	}{
		{"uid_store", `UID STORE 1 +FLAGS.SILENT (\Seen)`},
		{"seq_store", `STORE 1 +FLAGS.SILENT (\Seen)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()

			c := dialRawIMAP(t, server.Address)
			c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			for range 3 {
				c.appendMsg("INBOX", "Subject: condstore silent queued\r\n\r\nbody\r\n")
			}
			c.do("SELECT INBOX (CONDSTORE)")

			other := dialRawIMAP(t, server.Address)
			other.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			other.do("SELECT INBOX")
			other.do(`UID STORE 3 +FLAGS.SILENT (\Deleted)`)
			other.do("EXPUNGE")
			other.do(`UID STORE 1 +FLAGS.SILENT (\Answered)`)

			// Advance Poll cursor past UID 1's \Answered update while keeping
			// both Expunge(3) and Fetch(1, \Answered, M1) queued in tracker.
			preLines, _ := c.do("FETCH 2 (UID)")
			for _, line := range preLines {
				require.NotContains(t, line, "EXPUNGE", "precondition: EXPUNGE must stay queued: %q", preLines)
			}
			require.Empty(t, fetchLinesWithUID(preLines, 1), "precondition: UID 1 flag update must stay queued: %q", preLines)

			storeLines, _ := c.do(tc.command)
			noopLines, _ := c.do("NOOP")
			combined := append(storeLines, noopLines...)

			require.Contains(t, strings.Join(combined, "\n"), "* 3 EXPUNGE",
				"%s: queued EXPUNGE must be delivered: STORE %q, NOOP %q", tc.command, storeLines, noopLines)

			fetches := fetchLinesWithUID(combined, 1)
			require.NotEmpty(t, fetches, "%s: expected FETCH responses for UID 1: %q", tc.command, combined)

			var silentModSeq uint64
			var lastFlagsLine string
			for _, line := range fetches {
				if !strings.Contains(line, "FLAGS (") {
					silentModSeq = extractModSeq(t, line, tc.command)
				} else {
					lastFlagsLine = line
				}
			}
			require.NotZero(t, silentModSeq, "%s: expected .SILENT MODSEQ response: %q", tc.command, storeLines)
			require.NotEmpty(t, lastFlagsLine, "%s: expected FLAGS report for external change: %q", tc.command, combined)
			require.Regexp(t, seenFlagsRe, lastFlagsLine,
				"%s: final FLAGS lost .SILENT \\Seen update: STORE %q, NOOP %q", tc.command, storeLines, noopLines)
			require.Contains(t, lastFlagsLine, `\Answered`,
				"%s: final FLAGS lost external \\Answered update: STORE %q, NOOP %q", tc.command, storeLines, noopLines)

			lastModSeq := extractModSeq(t, fetches[len(fetches)-1], tc.command)
			require.GreaterOrEqual(t, lastModSeq, silentModSeq,
				"%s: final FETCH regressed MODSEQ (%d < %d): %q", tc.command, lastModSeq, silentModSeq, fetches)

			afterLines, _ := c.do("NOOP")
			require.Empty(t, fetchLinesWithUID(afterLines, 1), "%s: echoed again after sync: %q", tc.command, afterLines)
		})
	}
}

// While a NOTIFY MessageNew FETCH is paused loading body bytes from S3 after
// reading FLAGS () from the database, a concurrent STORE sets \Seen and writes
// its own FETCH (FLAGS (\Seen)) first. STORE must not suppress Poll via
// ownStoreEcho while fetchInFlight > 0; otherwise the resumed MessageNew FETCH
// writes stale FLAGS () last and Poll skips repairing it.
func TestIMAP_StoreNotOvertakenByInFlightNotifyFetch(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer server.Close()

	c := dialRawIMAP(t, server.Address)
	require.NoError(t, c.conn.SetDeadline(time.Now().Add(10*time.Second)))
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	c.do("SELECT INBOX")
	c.do("NOTIFY SET (SELECTED (MessageNew (FLAGS BINARY.PEEK[1]) MessageExpunge FlagChange))")

	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	defer release()

	var gets atomic.Int32
	fake.OnGet(func(string) {
		if gets.Add(1) == 1 {
			close(entered)
			<-resume
		}
	})
	defer fake.OnGet(nil)

	other := dialRawIMAP(t, server.Address)
	other.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	other.appendMsg("INBOX", binaryDecodeTestMessage("store notify overlap", "text/plain", "base64", "aGVsbG8gd29ybGQ=\r\n"))
	server.WaitForUploads(t)

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("notification did not reach body decode")
	}

	// Notification FLAGS () were already read before S3 Get paused. Send STORE,
	// which writes its own FETCH (FLAGS (\Seen) UID 1) immediately while the
	// post-command Poll waits for the in-flight notification's seqViewMu.RLock.
	tag := c.send(`UID STORE 1 +FLAGS (\Seen)`)
	var lines []string
	for {
		line, err := c.r.ReadString('\n')
		require.NoError(t, err)
		line = strings.TrimRight(line, "\r\n")
		lines = append(lines, line)
		if seenFlagsRe.MatchString(line) {
			break
		}
	}

	require.NoError(t, c.conn.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	line, err := c.r.ReadString('\n')
	var ne net.Error
	require.ErrorAs(t, err, &ne, "STORE completed before notification released: %q", line)
	require.True(t, ne.Timeout())

	require.NoError(t, c.conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	release()

	remaining, _ := c.collect(tag, "overlapped STORE")
	lines = append(lines, remaining...)
	noop, _ := c.do("NOOP")
	lines = append(lines, noop...)

	var last string
	for _, response := range fetchResponsesForSeq(lines, 1) {
		if strings.Contains(response, "FLAGS (") {
			last = response
		}
	}
	t.Logf("responses=%q", lines)
	require.Regexp(t, seenFlagsRe, last, "stale notification FETCH overtook STORE's \\Seen; final poll must repair it")
}
