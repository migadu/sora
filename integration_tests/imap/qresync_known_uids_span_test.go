//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestIMAP_QResyncSelectKnownUIDsCostFollowsRanges: a client that caches the oldest and
// the newest message of a mailbox with a long delivery and expunge history sends
// known-uids "<oldest>:<newest>" (#1354). The VANISHED (EARLIER) answer is one range,
// and computing it must cost memory in proportion to the ranges and the messages, not
// to the UID span: SELECT visited every UID of the range and appended each missing one
// to a slice, 5M entries and over 100 MB per SELECT here.
func TestIMAP_QResyncSelectKnownUIDsCostFollowsRanges(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupIMAPServer(t)
	t.Cleanup(server.Close)
	ctx := context.Background()

	const (
		mailbox = "Span"
		top     = 5_000_000 // UID of the newest message
		maxMiB  = 16        // the SELECT itself needs well under 1 MiB
	)
	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf(`LOGIN "%s" "%s"`, account.Email, account.Password))
	c.do("CREATE " + mailbox)
	msg := "From: a@example.com\r\nTo: b@example.com\r\nSubject: span\r\n\r\nhello\r\n"
	first := c.appendMsg(mailbox, msg)

	// UIDs first+1 .. top-1 were assigned and have all been expunged since.
	tag, err := server.ResilientDB.GetDatabase().GetWritePool().Exec(ctx, `
		UPDATE mailboxes m SET highest_uid = $3
		FROM credentials c
		WHERE c.account_id = m.account_id AND c.address = $1 AND m.name = $2`,
		account.Email, mailbox, top-1)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("raise highest_uid: %v (%d rows)", err, tag.RowsAffected())
	}
	last := c.appendMsg(mailbox, msg)
	if last != top {
		t.Fatalf("second APPEND got UID %d, want %d", last, top)
	}

	c.do("ENABLE QRESYNC")
	examined, _ := c.do("EXAMINE " + mailbox)
	m := regexp.MustCompile(`\[UIDVALIDITY (\d+)\]`).FindStringSubmatch(strings.Join(examined, "\n"))
	if m == nil {
		t.Fatalf("EXAMINE %s: no UIDVALIDITY in:\n%s", mailbox, strings.Join(examined, "\n"))
	}
	c.do("CLOSE")

	cmd := fmt.Sprintf("EXAMINE %s (QRESYNC (%s 1 %d:%d))", mailbox, m[1], first, last)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	untagged, _ := c.do(cmd)
	runtime.ReadMemStats(&after)

	want := fmt.Sprintf("* VANISHED (EARLIER) %d:%d", first+1, last-1)
	found := false
	for _, line := range untagged {
		if line == want {
			found = true
		}
	}
	if !found {
		t.Errorf("%s: want %q, got:\n%s", cmd, want, strings.Join(untagged, "\n"))
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > maxMiB<<20 {
		t.Errorf("%s allocated %.1f MiB in this process, want under %d MiB: the VANISHED "+
			"computation follows the UID span %d:%d instead of its ranges",
			cmd, float64(allocated)/(1<<20), maxMiB, first, last)
	}
}
