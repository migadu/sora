//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

func TestMessagesRepairState(t *testing.T) {
	rdb := setupTestDatabase(t)
	defer rdb.Close()
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)
	inbox, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "INBOX")
	require.NoError(t, err)

	var ids []int64
	for i := 0; i < 4; i++ {
		ids = append(ids, insertAdminTestMessage(t, ctx, rdb, accountID, inbox.ID, inbox.Name, fmt.Sprintf("state-%d", i)))
	}
	pool := rdb.GetOperationalDatabase().GetWritePool()
	_, err = pool.Exec(ctx, `DELETE FROM message_state WHERE message_id = ANY($1)`, ids[1:3])
	require.NoError(t, err)
	hasState := func(id int64) (ok bool) {
		t.Helper()
		require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM message_state WHERE message_id = $1)`, id).Scan(&ok))
		return ok
	}
	unseen := func() (n int) {
		t.Helper()
		require.NoError(t, pool.QueryRow(ctx, `SELECT unseen_count FROM mailbox_stats WHERE mailbox_id = $1`, inbox.ID).Scan(&n))
		return n
	}
	require.Equal(t, 2, unseen())

	out := runMessagesRepairState(t, ctx, "--batch-size", "1")
	for _, id := range ids {
		require.Contains(t, out, fmt.Sprintf("(resume with --start-after %d)", id))
	}
	require.Contains(t, out, fmt.Sprintf("Checked 4 message row(s) after id 0, up to id %d: 2 live message(s) without a state row, in 1 mailbox(es).", ids[3]))
	require.Contains(t, out, "Dry run: nothing was changed. Run again with --apply to repair them.")
	require.False(t, hasState(ids[1]))
	require.False(t, hasState(ids[2]))
	require.Equal(t, 2, unseen())

	out = runMessagesRepairState(t, ctx, "--start-after", strconv.FormatInt(ids[1], 10), "--apply")
	require.Contains(t, out, "1 live message(s) without a state row, in 1 mailbox(es).")
	require.Contains(t, out, "Gave 1 message(s) a state row with no flags")
	require.False(t, hasState(ids[1]))
	require.True(t, hasState(ids[2]))
	require.Equal(t, 3, unseen())

	out = runMessagesRepairState(t, ctx, "--apply")
	require.Contains(t, out, "Gave 1 message(s) a state row with no flags")
	require.True(t, hasState(ids[1]))
	require.Equal(t, 4, unseen())

	out = runMessagesRepairState(t, ctx)
	require.Contains(t, out, "0 live message(s) without a state row, in 0 mailbox(es).")
	require.NotContains(t, out, "Dry run:")
}

func runMessagesRepairState(t *testing.T, ctx context.Context, flags ...string) string {
	t.Helper()
	previousConfig, previousArgs, previousEvery := globalConfig, os.Args, repairStateProgressEvery
	t.Cleanup(func() {
		globalConfig, os.Args, repairStateProgressEvery = previousConfig, previousArgs, previousEvery
	})
	repairStateProgressEvery = 0
	globalConfig.Database = *adminTestDBConfig(t)
	os.Args = append([]string{"sora-admin", "messages", "repair-state"}, flags...)
	out := captureStdout(t, func() error {
		handleRepairMessageState(ctx)
		return nil
	})
	t.Logf("%s\n%s", strings.Join(os.Args[2:], " "), out)
	return out
}
