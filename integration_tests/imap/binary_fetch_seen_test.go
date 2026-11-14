//go:build integration

package imap_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// seenFlagsRe matches a FLAGS data item that carries \Seen.
var seenFlagsRe = regexp.MustCompile(`FLAGS \([^)]*\\Seen\b`)

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
