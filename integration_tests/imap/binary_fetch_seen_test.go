//go:build integration

package imap_test

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// seenFlagsRe matches a FLAGS data item that carries \Seen.
var seenFlagsRe = regexp.MustCompile(`FLAGS \([^)]*\\Seen\b`)

// modSeqItemRe extracts the numeric value from a MODSEQ (<n>) data item.
var modSeqItemRe = regexp.MustCompile(`MODSEQ \((\d+)\)`)

// uidItemRe extracts the numeric value from a UID <n> data item.
var uidItemRe = regexp.MustCompile(`\bUID (\d+)\b`)

// TestIMAP_FetchBinarySetsSeen: RFC 9051 §6.4.5 defines BINARY.PEEK as "An
// alternate form of BINARY[<section-binary>] that does not implicitly set the
// \Seen flag" (RFC 3516 §4.2: "An alternate form of FETCH BINARY that does not
// implicitly set the \Seen flag"), so BINARY[...] sets \Seen as BODY[...]
// does: "The \Seen flag is implicitly set; if this causes the flags to change,
// they SHOULD be included as part of the FETCH responses." FETCH BINARY[...]
// never set it (#873).
func TestIMAP_FetchBinarySetsSeen(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	defer server.Close()

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
	for range 3 {
		c.appendMsg("INBOX", binaryFetchTestMessage)
	}
	c.do("SELECT INBOX")

	fetch := func(cmd string) string {
		t.Helper()
		untagged, _ := c.do(cmd)
		return strings.Join(untagged, "\r\n")
	}
	seen := func(seq int) bool {
		t.Helper()
		return seenFlagsRe.MatchString(fetch(fmt.Sprintf("FETCH %d (FLAGS)", seq)))
	}

	// BINARY.PEEK[] and BINARY.SIZE[] leave \Seen alone.
	if resp := fetch("FETCH 1 (BINARY.PEEK[1] BINARY.SIZE[1])"); !strings.Contains(resp, "hello world") {
		t.Fatalf("FETCH 1 (BINARY.PEEK[1] BINARY.SIZE[1]): want the decoded BINARY[1], got:\n%s", resp)
	}
	if seen(1) {
		t.Errorf("FETCH (BINARY.PEEK[1] BINARY.SIZE[1]) set \\Seen")
	}

	// BINARY[] sets it, by sequence number and by UID, and the FETCH responses
	// report the change.
	for _, tc := range []struct {
		cmd string
		seq int
	}{
		{"FETCH 1 (BINARY[1])", 1},
		{"UID FETCH 2 (BINARY[1])", 2},
	} {
		resp := fetch(tc.cmd)
		if !strings.Contains(resp, "hello world") {
			t.Fatalf("%s: want the decoded BINARY[1], got:\n%s", tc.cmd, resp)
		}
		if !seenFlagsRe.MatchString(resp) {
			t.Errorf("%s: want the changed FLAGS in the FETCH responses, got:\n%s", tc.cmd, resp)
		}
		if !seen(tc.seq) {
			t.Errorf("%s did not set \\Seen", tc.cmd)
		}
	}

	// FLAGS fetched alongside BINARY[] carries the \Seen it just set.
	if resp := fetch("FETCH 3 (FLAGS BINARY[1])"); !seenFlagsRe.MatchString(resp) {
		t.Errorf("FETCH 3 (FLAGS BINARY[1]): want FLAGS with \\Seen, got:\n%s", resp)
	}
}

// splitUntaggedResponses groups rawIMAP untagged lines back into complete
// server responses so literals containing CRLF stay attached to their FETCH.
func splitUntaggedResponses(untagged []string) []string {
	var out []string
	for _, line := range untagged {
		if strings.HasPrefix(line, "* ") || len(out) == 0 {
			out = append(out, line)
		} else {
			out[len(out)-1] += "\r\n" + line
		}
	}
	return out
}

func extractModSeq(t *testing.T, s, ctx string) uint64 {
	t.Helper()
	m := modSeqItemRe.FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("%s: missing MODSEQ item in:\n%s", ctx, s)
	}
	v, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		t.Fatalf("%s: invalid MODSEQ %q: %v", ctx, m[1], err)
	}
	return v
}

// TestIMAP_FetchImplicitSeenFlagsAndModSeq verifies that when a non-PEEK FETCH
// (BINARY[...] or BODY[...]) implicitly sets \Seen:
//  1. The FETCH response's own MODSEQ reflects the post-update mod-sequence
//     created by setting \Seen, never the stale pre-FETCH mod-sequence.
//  2. When FLAGS was not explicitly requested, the FETCH response itself still
//     includes FLAGS (\Seen ...) when \Seen changed (RFC 3501 §6.4.5 / RFC 9051
//     §6.4.5), plus MODSEQ when CONDSTORE is enabled on the session (RFC 7162
//     §3.1.3 / §3.2) and UID when QRESYNC is enabled (RFC 7162 §3.2.4), even
//     when NOTIFY suppresses FlagChange responses from Poll.
func TestIMAP_FetchImplicitSeenFlagsAndModSeq(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	t.Run("solicited MODSEQ reflects implicit Seen update", func(t *testing.T) {
		server, account := common.SetupIMAPServer(t)
		defer server.Close()

		c := dialRawIMAP(t, server.Address)
		c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
		for range 3 {
			c.appendMsg("INBOX", binaryFetchTestMessage)
		}
		c.do("SELECT INBOX")

		pre := make([]uint64, 4)
		var uid3 string
		for seq := 1; seq <= 3; seq++ {
			untagged, _ := c.do(fmt.Sprintf("FETCH %d (UID MODSEQ)", seq))
			joined := strings.Join(untagged, "\r\n")
			pre[seq] = extractModSeq(t, joined, fmt.Sprintf("pre FETCH %d", seq))
			if seq == 3 {
				m := uidItemRe.FindStringSubmatch(joined)
				if m == nil {
					t.Fatalf("FETCH 3 (UID MODSEQ): missing UID in %q", joined)
				}
				uid3 = m[1]
			}
		}

		for _, tc := range []struct {
			seq        int
			cmd        string
			wantMarker string
		}{
			{1, "FETCH 1 (FLAGS MODSEQ BINARY[1])", "BINARY[1]"},
			{2, "FETCH 2 (FLAGS MODSEQ BODY[1])", "BODY[1]"},
			{3, fmt.Sprintf("UID FETCH %s (FLAGS BINARY[1]) (CHANGEDSINCE 0)", uid3), "BINARY[1]"},
		} {
			untagged, _ := c.do(tc.cmd)
			var bodyFetch string
			for _, resp := range splitUntaggedResponses(untagged) {
				if strings.Contains(resp, tc.wantMarker) {
					bodyFetch = resp
					break
				}
			}
			if bodyFetch == "" {
				t.Fatalf("%s: no FETCH response carrying %s in:\n%s", tc.cmd, tc.wantMarker, strings.Join(untagged, "\r\n"))
			}
			if !seenFlagsRe.MatchString(bodyFetch) {
				t.Errorf("%s: want FLAGS with \\Seen in FETCH response, got:\n%s", tc.cmd, bodyFetch)
			}
			gotModSeq := extractModSeq(t, bodyFetch, tc.cmd)
			if gotModSeq <= pre[tc.seq] {
				t.Errorf("%s: FETCH response carried stale pre-Seen MODSEQ %d (pre=%d):\n%s", tc.cmd, gotModSeq, pre[tc.seq], bodyFetch)
			}
			afterUntagged, _ := c.do(fmt.Sprintf("FETCH %d (MODSEQ)", tc.seq))
			storedModSeq := extractModSeq(t, strings.Join(afterUntagged, "\r\n"), "stored MODSEQ")
			if gotModSeq != storedModSeq {
				t.Errorf("%s: FETCH response MODSEQ %d != stored post-Seen MODSEQ %d", tc.cmd, gotModSeq, storedModSeq)
			}
		}
	})

	t.Run("unrequested FLAGS included without CONDSTORE under NOTIFY", func(t *testing.T) {
		server, account := common.SetupIMAPServer(t)
		defer server.Close()

		c := dialRawIMAP(t, server.Address)
		c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
		for range 2 {
			c.appendMsg("INBOX", binaryFetchTestMessage)
		}
		c.do("SELECT INBOX")
		c.do("NOTIFY SET (SELECTED (MessageNew MessageExpunge))")

		for _, tc := range []struct {
			cmd  string
			want string
		}{
			{"FETCH 1 (BINARY[1])", "hello world"},
			{"FETCH 2 (BODY[1])", "aGVsbG8gd29ybGQ="},
		} {
			untagged, _ := c.do(tc.cmd)
			resp := strings.Join(untagged, "\r\n")
			if !strings.Contains(resp, tc.want) {
				t.Fatalf("%s: missing body payload %q in:\n%s", tc.cmd, tc.want, resp)
			}
			if !seenFlagsRe.MatchString(resp) {
				t.Errorf("%s: want FLAGS (\\Seen ...) in FETCH response when Poll FlagChange is suppressed, got:\n%s", tc.cmd, resp)
			}
			if strings.Contains(resp, "MODSEQ") {
				t.Errorf("%s: must not emit MODSEQ when CONDSTORE was never enabled, got:\n%s", tc.cmd, resp)
			}
		}

		// Re-fetching an already-\Seen message does not change flags, so unrequested
		// FLAGS must not be added on the repeat fetch.
		untagged, _ := c.do("FETCH 1 (BINARY[1])")
		if resp := strings.Join(untagged, "\r\n"); strings.Contains(resp, "FLAGS (") {
			t.Errorf("repeat FETCH 1 (BINARY[1]) on already-Seen message emitted unrequested FLAGS:\n%s", resp)
		}
	})

	t.Run("unrequested FLAGS and MODSEQ included with CONDSTORE under NOTIFY", func(t *testing.T) {
		server, account := common.SetupIMAPServer(t)
		defer server.Close()

		c := dialRawIMAP(t, server.Address)
		c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
		for range 2 {
			c.appendMsg("INBOX", binaryFetchTestMessage)
		}
		c.do("SELECT INBOX (CONDSTORE)")

		pre1Untagged, _ := c.do("FETCH 1 (MODSEQ)")
		pre1 := extractModSeq(t, strings.Join(pre1Untagged, "\r\n"), "pre1")
		pre2Untagged, _ := c.do("FETCH 2 (UID MODSEQ)")
		pre2Joined := strings.Join(pre2Untagged, "\r\n")
		pre2 := extractModSeq(t, pre2Joined, "pre2")
		uid2Match := uidItemRe.FindStringSubmatch(pre2Joined)
		if uid2Match == nil {
			t.Fatalf("FETCH 2 (UID MODSEQ): missing UID in %q", pre2Joined)
		}

		c.do("NOTIFY SET (SELECTED (MessageNew MessageExpunge))")
		untagged1, _ := c.do("FETCH 1 (BINARY[1])")
		resp1 := strings.Join(untagged1, "\r\n")
		if !seenFlagsRe.MatchString(resp1) {
			t.Errorf("FETCH 1 (BINARY[1]): want FLAGS (\\Seen ...), got:\n%s", resp1)
		}
		if got1 := extractModSeq(t, resp1, "FETCH 1 (BINARY[1])"); got1 <= pre1 {
			t.Errorf("FETCH 1 (BINARY[1]): want MODSEQ > %d, got %d:\n%s", pre1, got1, resp1)
		}

		c.do("NOTIFY NONE")
		cmd2 := fmt.Sprintf("UID FETCH %s (BODY[1])", uid2Match[1])
		untagged2, _ := c.do(cmd2)
		resp2 := strings.Join(untagged2, "\r\n")
		if !seenFlagsRe.MatchString(resp2) {
			t.Errorf("%s: want FLAGS (\\Seen ...), got:\n%s", cmd2, resp2)
		}
		if got2 := extractModSeq(t, resp2, cmd2); got2 <= pre2 {
			t.Errorf("%s: want MODSEQ > %d, got %d:\n%s", cmd2, pre2, got2, resp2)
		}
	})

	t.Run("QRESYNC sequence FETCH includes UID FLAGS and MODSEQ on implicit Seen", func(t *testing.T) {
		server, account := common.SetupIMAPServer(t)
		defer server.Close()

		c := dialRawIMAP(t, server.Address)
		c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
		c.do("ENABLE QRESYNC")
		c.appendMsg("INBOX", binaryFetchTestMessage)
		c.do("SELECT INBOX")
		c.do("NOTIFY NONE")

		untagged, _ := c.do("FETCH 1 (BINARY[1])")
		resp := strings.Join(untagged, "\r\n")
		if !seenFlagsRe.MatchString(resp) {
			t.Errorf("FETCH 1 (BINARY[1]) under QRESYNC: want FLAGS (\\Seen ...), got:\n%s", resp)
		}
		if !uidItemRe.MatchString(resp) {
			t.Errorf("FETCH 1 (BINARY[1]) under QRESYNC: want UID item (RFC 7162 §3.2.4), got:\n%s", resp)
		}
		extractModSeq(t, resp, "FETCH 1 (BINARY[1]) under QRESYNC")
	})
}
