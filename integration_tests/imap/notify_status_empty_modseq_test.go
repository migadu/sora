//go:build integration

package imap_test

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestNotifySetStatusEmptyMailboxHighestModSeq: the initial STATUS responses
// of NOTIFY SET STATUS (RFC 5465 section 3.1) must report the same
// HIGHESTMODSEQ as STATUS for a mailbox that has never held a message. 0
// would tell a CONDSTORE client that the mailbox has no persistent
// mod-sequences (RFC 7162 section 7, status-att-val), and sending it back as
// CHANGEDSINCE or a QRESYNC parameter is a BAD (mod-sequence-value is >= 1).
func TestNotifySetStatusEmptyMailboxHighestModSeq(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()

	c := dialRawIMAP(t, srv.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	c.do("ENABLE CONDSTORE")
	c.do("CREATE Empty")

	statusLines, _ := c.do("STATUS Empty (HIGHESTMODSEQ UIDVALIDITY)")
	want := statusHighestModSeq(t, statusLines, "Empty")
	if want < 1 {
		t.Fatalf("STATUS reported HIGHESTMODSEQ %d for an empty mailbox, want >= 1: %q", want, statusLines)
	}

	notifyLines, _ := c.do("NOTIFY SET STATUS (personal (MessageNew MessageExpunge FlagChange))")
	if got := statusHighestModSeq(t, notifyLines, "Empty"); got != want {
		t.Errorf("NOTIFY SET STATUS reported HIGHESTMODSEQ %d for the empty mailbox, STATUS reported %d: %q", got, want, notifyLines)
	}
}

// statusHighestModSeq returns the HIGHESTMODSEQ of the untagged STATUS
// response for mailbox among lines.
func statusHighestModSeq(t *testing.T, lines []string, mailbox string) uint64 {
	t.Helper()
	re := regexp.MustCompile(`^\* STATUS "?` + regexp.QuoteMeta(mailbox) + `"? \(.*\bHIGHESTMODSEQ (\d+)`)
	for _, line := range lines {
		if m := re.FindStringSubmatch(line); m != nil {
			v, err := strconv.ParseUint(m[1], 10, 64)
			if err != nil {
				t.Fatalf("bad HIGHESTMODSEQ in %q: %v", line, err)
			}
			return v
		}
	}
	t.Fatalf("no STATUS with HIGHESTMODSEQ for %q in %q", mailbox, lines)
	return 0
}
