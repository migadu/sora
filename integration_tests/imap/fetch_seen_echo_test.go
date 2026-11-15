//go:build integration

package imap_test

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// fetchResponsesForSeq returns the FETCH responses for message seq, each with
// its literals attached.
func fetchResponsesForSeq(untagged []string, seq int) []string {
	prefix := fmt.Sprintf("* %d FETCH ", seq)
	var out []string
	for _, resp := range splitUntaggedResponses(untagged) {
		if strings.HasPrefix(resp, prefix) {
			out = append(out, resp)
		}
	}
	return out
}

// requireSeenAnsweredOnce runs a FETCH that implicitly sets \Seen on the
// messages seqs and asserts that each is reported exactly once, by the FETCH
// response itself (RFC 9051 §6.4.5: "if this causes the flags to change, they
// SHOULD be included as part of the FETCH responses"), and neither by the
// command-boundary poll nor by the next NOOP.
func requireSeenAnsweredOnce(t *testing.T, c *rawIMAP, command string, condStore bool, seqs ...int) {
	t.Helper()
	lines, _ := c.do(command)
	for _, seq := range seqs {
		fetches := fetchResponsesForSeq(lines, seq)
		require.Len(t, fetches, 1, "%s: one FETCH for message %d: %q", command, seq, lines)
		require.Regexp(t, seenFlagsRe, fetches[0], command)
		if condStore {
			require.Contains(t, fetches[0], "MODSEQ (", command)
		} else {
			require.NotContains(t, fetches[0], "MODSEQ", command)
		}
	}

	lines, _ = c.do("NOOP")
	for _, seq := range seqs {
		require.Empty(t, fetchResponsesForSeq(lines, seq), "%s: implicit \\Seen of message %d echoed by the next poll: %q", command, seq, lines)
	}
}

// A non-PEEK FETCH that sets \Seen reports the change in its own FETCH
// response; the post-command poll must not report it a second time (#1180),
// while another session is still told of it.
func TestIMAP_FetchImplicitSeenReportedOnce(t *testing.T) {
	for name, condStore := range map[string]bool{"plain": false, "condstore": true} {
		t.Run(name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()

			c := dialRawIMAP(t, server.Address)
			c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			for range 5 {
				c.appendMsg("INBOX", binaryFetchTestMessage)
			}
			if condStore {
				c.do("ENABLE CONDSTORE")
			}
			c.do("SELECT INBOX")

			other := dialRawIMAP(t, server.Address)
			other.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			other.do("SELECT INBOX")

			for _, step := range []struct {
				command string
				seqs    []int
			}{
				{"FETCH 1 BODY[TEXT]", []int{1}},
				{"UID FETCH 2 BODY[TEXT]", []int{2}},
				{"FETCH 3 (BINARY[1])", []int{3}},
				{"FETCH 4:5 BODY[]", []int{4, 5}},
			} {
				requireSeenAnsweredOnce(t, c, step.command, condStore, step.seqs...)

				lines, _ := other.do("NOOP")
				for _, seq := range step.seqs {
					fetches := fetchResponsesForSeq(lines, seq)
					require.Len(t, fetches, 1, "%s: other session must be notified of message %d: %q", step.command, seq, lines)
					require.Regexp(t, seenFlagsRe, fetches[0], step.command)
				}
			}

			// Fetching a message that is already \Seen changes nothing and
			// reports no FLAGS, and another session's change after it still is.
			lines, _ := c.do("FETCH 1 BODY[TEXT]")
			require.NotContains(t, strings.Join(lines, "\n"), "FLAGS (", "%q", lines)
			other.do(`STORE 1 +FLAGS.SILENT (\Flagged)`)
			lines, _ = c.do("NOOP")
			fetches := fetchResponsesForSeq(lines, 1)
			require.Len(t, fetches, 1, "%q", lines)
			require.Contains(t, fetches[0], `\Flagged`)
		})
	}
}

// Under a NOTIFY watch with FlagChange the pump polls concurrently with the
// FETCH; it must not report the implicit \Seen the FETCH response carried
// either, whether its tick lands during the FETCH or after it.
func TestIMAP_FetchImplicitSeenNotEchoedByNotify(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	for range 4 {
		c.appendMsg("INBOX", binaryFetchTestMessage)
	}
	c.do("SELECT INBOX")
	c.do("NOTIFY SET (SELECTED (MessageNew MessageExpunge FlagChange))")

	for _, step := range []struct {
		command string
		seqs    []int
	}{
		{"FETCH 1 BODY[TEXT]", []int{1}},
		{"UID FETCH 2 (BINARY[1])", []int{2}},
		{"FETCH 3:4 BODY[]", []int{3, 4}},
	} {
		lines, _ := c.do(step.command)
		for _, seq := range step.seqs {
			require.Len(t, fetchResponsesForSeq(lines, seq), 1, "%s: message %d: %q", step.command, seq, lines)
		}

		time.Sleep(time.Second) // several NOTIFY ticks (300ms in this package)
		lines, _ = c.do("NOOP")
		for _, seq := range step.seqs {
			require.Empty(t, fetchResponsesForSeq(lines, seq), "%s: implicit \\Seen of message %d echoed by the NOTIFY pump: %q", step.command, seq, lines)
		}
	}
}

// A FETCH may not send an EXPUNGE (RFC 3501 §7.4.1), so the poll that ends a
// sequence FETCH leaves the EXPUNGE, and every update queued after it, held
// until the next command that may send it. When a held update is an older
// state of the message whose \Seen the next FETCH sets, it reaches the client
// after that FETCH's response, so the poll must report the message's current
// state again behind it: the last flags the client receives must carry \Seen.
func TestIMAP_FetchImplicitSeenNotOvertakenByHeldUpdate(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	for range 3 {
		c.appendMsg("INBOX", binaryFetchTestMessage)
	}
	c.do("SELECT INBOX")

	other := dialRawIMAP(t, server.Address)
	other.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	other.do("SELECT INBOX")
	other.do(`UID STORE 3 +FLAGS.SILENT (\Deleted)`)
	other.do("UID EXPUNGE 3")
	other.do(`UID STORE 1 +FLAGS.SILENT (\Answered)`)

	// The sequence FETCH queues the EXPUNGE and then the other session's
	// change to message 1, and may send neither.
	lines, _ := c.do("FETCH 1 (UID)")
	for _, line := range lines {
		require.NotContains(t, line, "EXPUNGE", "precondition: the EXPUNGE is held: %q", lines)
		require.NotContains(t, line, "FLAGS (", "precondition: the flag change is held: %q", lines)
	}

	fetchLines, _ := c.do("FETCH 1 BODY[TEXT]")
	noopLines, _ := c.do("NOOP")
	require.Contains(t, strings.Join(noopLines, "\n"), "* 3 EXPUNGE")
	var last string
	for _, resp := range fetchResponsesForSeq(append(fetchLines, noopLines...), 1) {
		if strings.Contains(resp, "FLAGS (") {
			last = resp
		}
	}
	require.NotEmpty(t, last, "no flags reported: FETCH %q, NOOP %q", fetchLines, noopLines)
	require.Regexp(t, seenFlagsRe, last, "the last flags sent for the message are an older state: FETCH %q, NOOP %q", fetchLines, noopLines)
	require.Contains(t, last, `\Answered`)

	lines, _ = c.do("NOOP")
	require.Empty(t, fetchResponsesForSeq(lines, 1), "reported again: %q", lines)
}

// A FETCH that fails part way has set \Seen on every message of the batch,
// but answered only the messages before the failure. The poll must report the
// others, or the client never learns of their \Seen, and must still not
// repeat the ones the FETCH answered.
func TestIMAP_FetchImplicitSeenUnansweredLeftToPoll(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServer(t)
	defer server.Close()

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
	c.appendMsg("INBOX", binaryFetchTestMessage)
	// A transfer encoding the server cannot decode: BINARY fails the request
	// with NO [UNKNOWN-CTE] at this message (RFC 9051 §7.5.2).
	c.appendMsg("INBOX", binaryDecodeTestMessage("cte", "text/plain", "x-uuencode", "begin 644 a.txt\r\n#86)C\r\n`\r\nend\r\n"))
	c.appendMsg("INBOX", binaryFetchTestMessage)
	c.do("SELECT INBOX")
	lines, _ := c.do("FETCH 1:3 (FLAGS)")
	require.NotRegexp(t, seenFlagsRe, strings.Join(lines, "\n"), "precondition: no message is \\Seen")

	tag := c.send("FETCH 1:3 (BINARY[1])")
	fetchLines, tagged := c.read(tag, "FETCH 1:3 (BINARY[1])")
	require.Contains(t, tagged, " NO [UNKNOWN-CTE] ")
	require.Len(t, fetchResponsesForSeq(fetchLines, 1), 1, "%q", fetchLines)
	require.Regexp(t, seenFlagsRe, fetchResponsesForSeq(fetchLines, 1)[0])

	noopLines, _ := c.do("NOOP")
	require.Empty(t, fetchResponsesForSeq(noopLines, 1), "the answered \\Seen of message 1 echoed: %q", noopLines)

	// Every message whose stored flags now carry \Seen was told so.
	lines, _ = c.do("FETCH 2:3 (FLAGS)")
	for _, seq := range []int{2, 3} {
		stored := fetchResponsesForSeq(lines, seq)
		require.Len(t, stored, 1, "%q", lines)
		if !seenFlagsRe.MatchString(stored[0]) {
			continue
		}
		reported := false
		for _, resp := range fetchResponsesForSeq(append(fetchLines, noopLines...), seq) {
			reported = reported || seenFlagsRe.MatchString(resp)
		}
		require.True(t, reported, "message %d is \\Seen but the client was never told: FETCH %q, NOOP %q", seq, fetchLines, noopLines)
	}
	// A failed batch must also end its in-flight snapshot, or a later quiet
	// FETCH would keep losing echo suppression.
	c.appendMsg("INBOX", binaryFetchTestMessage)
	requireSeenAnsweredOnce(t, c, "FETCH 4 BODY[TEXT]", false, 4)

}

// A UID not yet announced by EXISTS has no response sequence number. Filtering
// it before the implicit Seen update also keeps an unanswered message unread.
func TestIMAP_FetchImplicitSeenSkipsUnannouncedUID(t *testing.T) {
	viewer, other := twoSessions(t, 3)
	other.append("s1", "INBOX", msg(4))
	_, tagged := other.cmd("s2", "SELECT INBOX")
	require.Contains(t, tagged, "OK")
	_, tagged = other.cmd("s3", `UID STORE 1 +FLAGS.SILENT (\Deleted)`)
	require.Contains(t, tagged, "OK")
	_, tagged = other.cmd("s4", "EXPUNGE")
	require.Contains(t, tagged, "OK")
	queued, tagged := viewer.cmd("s5", "FETCH 2 (UID)")
	require.Contains(t, tagged, "OK")
	require.Empty(t, expungeSeqs(queued))
	require.Zero(t, existsCount(queued))
	lines, tagged := viewer.cmd("s6", "UID FETCH 4 BODY[]")
	require.Contains(t, tagged, "OK")
	beforeUpdates := lines[:firstIndexOfResponse(lines, "EXPUNGE")]
	require.Empty(t, seqUIDPairs(beforeUpdates), "unannounced UID must not get a response")
	require.NotContains(t, flagsOfUID(t, viewer, "4"), `\Seen`, "unanswered UID was marked Seen")
}

// The NOTIFY pump takes a batch of updates off the session tracker and then
// writes it, and a client that reads slowly keeps it writing. A FETCH that
// sets \Seen, or a STORE, of a message whose older state is still in that
// batch must not slip its answer in ahead of that state: the answer is
// recorded so the poll does not repeat it, so the older state written after it
// would be the client's last view of the message.
func TestIMAP_OwnAnswerNotOvertakenByNotifyDelivery(t *testing.T) {
	for name, command := range map[string]string{
		"fetch": "UID FETCH %d BODY[TEXT]",
		"store": `UID STORE %d +FLAGS (\Seen)`,
	} {
		t.Run(name, func(t *testing.T) {
			common.SkipIfDatabaseUnavailable(t)
			server, owner := common.SetupIMAPServer(t)
			defer server.Close()

			c := dialRawIMAP(t, server.Address)
			c.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			const messages = 200
			var lastUID imap.UID
			for range messages {
				lastUID = c.appendMsg("INBOX", binaryFetchTestMessage)
			}
			c.do("SELECT INBOX")
			c.do("NOTIFY SET (SELECTED (MessageNew MessageExpunge FlagChange))")
			require.NoError(t, c.conn.(*net.TCPConn).SetReadBuffer(4096))

			// One STORE gives every message long keywords: the pump takes all
			// of the changes in one batch, the last message's (without \Seen)
			// at its end, and blocks writing it while this client reads nothing.
			other := dialRawIMAP(t, server.Address)
			other.do(fmt.Sprintf("LOGIN %s %s", owner.Email, owner.Password))
			other.do("SELECT INBOX")
			keywords := make([]string, 40)
			for i := range keywords {
				keywords[i] = fmt.Sprintf("k%02d%s", i, strings.Repeat("x", 90))
			}
			other.do("STORE 1:* +FLAGS.SILENT (" + strings.Join(keywords, " ") + ")")
			time.Sleep(time.Second)

			cmd := fmt.Sprintf(command, lastUID)
			tag := c.send(cmd)
			time.Sleep(500 * time.Millisecond) // the command reaches its answer
			lines, tagged := c.read(tag, cmd)
			require.True(t, strings.HasPrefix(tagged, tag+" OK"), tagged)
			noopLines, _ := c.do("NOOP")

			// In the order received: whether each FLAGS of the message carried
			// \Seen.
			var seen []bool
			for _, resp := range fetchResponsesForSeq(append(lines, noopLines...), messages) {
				if strings.Contains(resp, "FLAGS (") {
					seen = append(seen, seenFlagsRe.MatchString(resp))
				}
			}
			require.NotEmpty(t, seen, "no flags reported for message %d", messages)
			require.True(t, seen[len(seen)-1], "%s: the last flags sent for the message are an older state (\\Seen in each FLAGS received: %v)", cmd, seen)
		})
	}
}
