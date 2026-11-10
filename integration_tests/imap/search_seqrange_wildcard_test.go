//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// A sequence range with "*" names the last message even when its other end is
// past it (RFC 3501 §9, seq-range): on a mailbox of two messages 99:* is 2:99.
func TestIMAP_SearchSortThread_SeqRangeWildcardPastEnd(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	for i := 1; i <= 3; i++ {
		c.appendMsg("INBOX", fmt.Sprintf("Message-ID: <seqrange%d@example.com>\r\nSubject: Solo %d\r\n\r\nbody\r\n", i, i))
	}
	c.do("SELECT INBOX")
	c.do(`STORE 1 +FLAGS (\Deleted)`)
	c.do("EXPUNGE")
	// Sequence 1 = UID 2, sequence 2 = UID 3.
	for _, tc := range []struct{ cmd, want string }{
		{"SEARCH 99:*", "* SEARCH 2"},
		{"SEARCH *:99", "* SEARCH 2"},
		{"UID SEARCH 99:*", "* SEARCH 3"},
		{"SEARCH NOT 99:*", "* SEARCH 1"},
		{"SEARCH OR 99:* 1", "* SEARCH 1 2"},
		{"SEARCH 2:*", "* SEARCH 2"},
		{"SEARCH *", "* SEARCH 2"},
		{"SEARCH 99", "* SEARCH"},
		{"SORT (ARRIVAL) UTF-8 99:*", "* SORT 2"},
		{"UID SORT (ARRIVAL) UTF-8 *:99", "* SORT 3"},
		{"THREAD REFERENCES UTF-8 99:*", "* THREAD (2)"},
		{"UID THREAD REFERENCES UTF-8 99:*", "* THREAD (3)"},
	} {
		t.Run(tc.cmd, func(t *testing.T) {
			parentTest := c.t
			c.t = t
			defer func() { c.t = parentTest }()
			lines, _ := c.do(tc.cmd)
			got := "(none)"
			for _, line := range lines {
				for _, kind := range []string{"* SEARCH", "* SORT", "* THREAD"} {
					if strings.HasPrefix(line, kind) {
						got = strings.TrimSpace(line)
					}
				}
			}
			if got != tc.want {
				t.Errorf("%s = %q, want %q", tc.cmd, got, tc.want)
			}
		})
	}
}
