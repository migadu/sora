//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/stretchr/testify/require"
)

func repairMissingMessageState(t *testing.T, rdb *resilient.ResilientDatabase, allTestIDs []int64, want ...int64) {
	t.Helper()
	ctx := context.Background()
	first := slices.Min(allTestIDs)
	last := slices.Max(allTestIDs)
	var found []int64
	for after := first - 1; after < last; {
		batch, err := rdb.FindMissingMessageStateWithRetry(ctx, after, 100)
		require.NoError(t, err)
		require.NotZero(t, batch.Scanned, "the scan ended before reaching message %d", last)
		for _, m := range batch.Missing {
			if slices.Contains(allTestIDs, m.ID) {
				found = append(found, m.ID)
			}
		}
		after = batch.LastID
	}
	require.Equal(t, want, found, "the scan finds exactly the test messages without a state row")
	repair, err := rdb.AddMissingMessageStateWithRetry(ctx, found)
	require.NoError(t, err)
	require.Equal(t, int64(len(want)), repair.Added)
}

var statusUnseenRe = regexp.MustCompile(`UNSEEN (\d+)`)

func TestIMAP_RepairedMissingStateIsUnseenAndStorable(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, account := common.SetupIMAPServer(t)
	defer server.Close()
	rdb := server.ResilientDB
	ctx := context.Background()

	c := dialRawIMAP(t, server.Address)
	c.do(fmt.Sprintf("LOGIN %s %s", account.Email, account.Password))
	for i := 1; i <= 4; i++ {
		c.appendMsg("INBOX", fmt.Sprintf("From: a@example.com\r\nTo: b@example.com\r\nSubject: state %d\r\n\r\nbody %d\r\n", i, i))
	}
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	inbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)
	pool := rdb.GetOperationalDatabase().GetWritePool()
	var ids []int64
	rows, err := pool.Query(ctx, `SELECT id FROM messages WHERE mailbox_id = $1 AND expunged_at IS NULL ORDER BY uid`, inbox.ID)
	require.NoError(t, err)
	for rows.Next() {
		var id int64
		require.NoError(t, rows.Scan(&id))
		ids = append(ids, id)
	}
	require.NoError(t, rows.Err())
	require.Len(t, ids, 4)
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := pool.Exec(ctx, sql, args...)
		require.NoError(t, err)
	}

	// Message 1 keeps its row (\Seen + Work). Messages 2, 3, and 4 lose their state rows.
	exec(`UPDATE message_state SET flags = flags | 1, custom_flags = '["Work"]' WHERE message_id = $1`, ids[0])
	exec(`DELETE FROM message_state WHERE message_id = $1`, ids[1])
	exec(`UPDATE messages SET expunged_at = now(), expunged_modseq = nextval('messages_modseq') WHERE id = $1`, ids[2])
	exec(`DELETE FROM message_state WHERE message_id = $1`, ids[2])
	exec(`UPDATE messages SET expunged_at = NULL, expunged_modseq = NULL WHERE id = $1`, ids[2])
	exec(`DELETE FROM message_state WHERE message_id = $1`, ids[3])

	statusUnseen := func() int {
		t.Helper()
		lines, _ := c.do("STATUS INBOX (MESSAGES UNSEEN)")
		for _, l := range lines {
			if m := statusUnseenRe.FindStringSubmatch(l); m != nil {
				require.Contains(t, l, "MESSAGES 4")
				return mustAtoi(t, m[1])
			}
		}
		t.Fatalf("no UNSEEN in STATUS response: %q", lines)
		return 0
	}
	search := func(criteria string) []imap.UID {
		t.Helper()
		lines, _ := c.do("SEARCH " + criteria)
		return parseSearchUIDs(lines)
	}

	c.do("SELECT INBOX")
	lines, _ := c.do("FETCH 2:4 (FLAGS)")
	require.Regexp(t, `FLAGS \((?:\\Recent)?\)`, fetchResponsesForSeq(lines, 2)[0])
	require.Regexp(t, `FLAGS \((?:\\Recent)?\)`, fetchResponsesForSeq(lines, 3)[0])
	require.Regexp(t, `FLAGS \((?:\\Recent)?\)`, fetchResponsesForSeq(lines, 4)[0])

	// Even BEFORE running repair-state, online STORE on message 4 creates its state row!
	c.do(`STORE 4 +FLAGS (\Seen)`)
	lines, _ = c.do("FETCH 4 (FLAGS)")
	require.Contains(t, fetchResponsesForSeq(lines, 4)[0], `\Seen`)

	// Repair remaining stateless messages 2 and 3 via messages repair-state.
	repairMissingMessageState(t, rdb, ids, ids[1], ids[2])

	require.Equal(t, 2, statusUnseen())
	require.Equal(t, []imap.UID{2, 3}, search("UNSEEN"))
	require.Equal(t, []imap.UID{2, 3}, search("NOT SEEN"))
	require.Equal(t, []imap.UID{2, 3, 4}, search("UNKEYWORD Work"))
	require.Equal(t, []imap.UID{2, 3, 4}, search("NOT KEYWORD Work"))
	require.Equal(t, []imap.UID{1, 4}, search("SEEN"))

	lines, _ = c.do("SELECT INBOX")
	require.Contains(t, strings.Join(lines, "\n"), "[UNSEEN 2]", "%q", lines)

	c.do(`STORE 2 +FLAGS (\Seen)`)
	c.do(`STORE 3 +FLAGS (Work)`)
	lines, _ = c.do("FETCH 2:3 (FLAGS)")
	require.Regexp(t, `FLAGS \(\\Seen\)`, fetchResponsesForSeq(lines, 2)[0])
	require.Contains(t, fetchResponsesForSeq(lines, 3)[0], "FLAGS (Work)")
	require.Equal(t, 1, statusUnseen())
	require.Equal(t, []imap.UID{3}, search("UNSEEN"))
}
