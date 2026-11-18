//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestMailboxRepairUnseen: "mailbox repair-unseen" reports the mailboxes whose cached
// unseen count differs from the number of unseen messages they hold, changes nothing
// until --apply is given, and then recomputes them.
func TestMailboxRepairUnseen(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByEmailWithRetry(ctx, account.Email)
	require.NoError(t, err)
	for _, name := range []string{"Drifted", "Right", "Stateless"} {
		require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, name, nil))
	}
	drifted, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "Drifted")
	require.NoError(t, err)
	right, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "Right")
	require.NoError(t, err)
	stateless, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, "Stateless")
	require.NoError(t, err)

	// Three unseen messages in Drifted, two of them deleted the way the hard deletes
	// before #1564 did, which leaves them counted; one in Right.
	var ids []int64
	for i := 0; i < 3; i++ {
		ids = append(ids, insertAdminTestMessage(t, ctx, rdb, accountID, drifted.ID, drifted.Name, fmt.Sprintf("drifted-%d", i)))
	}
	insertAdminTestMessage(t, ctx, rdb, accountID, right.ID, right.Name, "right")
	pool := rdb.GetOperationalDatabase().GetWritePool()
	_, err = pool.Exec(ctx, `DELETE FROM messages WHERE id = ANY($1)`, ids[:2])
	require.NoError(t, err)
	cached := func(mailboxID int64) (n int64) {
		t.Helper()
		require.NoError(t, pool.QueryRow(ctx, `SELECT unseen_count FROM mailbox_stats WHERE mailbox_id = $1`, mailboxID).Scan(&n))
		return n
	}
	require.Equal(t, int64(3), cached(drifted.ID))

	// One unseen message in Stateless whose message_state row an older build left
	// missing, with the cached count such a build kept: it did not count the message
	// (#1949), which SEARCH UNSEEN matches.
	statelessID := insertAdminTestMessage(t, ctx, rdb, accountID, stateless.ID, stateless.Name, "stateless")
	_, err = pool.Exec(ctx, `DELETE FROM message_state WHERE message_id = $1`, statelessID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE mailbox_stats SET unseen_count = 0 WHERE mailbox_id = $1`, stateless.ID)
	require.NoError(t, err)

	wouldRepair := fmt.Sprintf(`WOULD REPAIR mailbox_id=%d account_id=%d "Drifted" unseen_count 3 -> 1`, drifted.ID, accountID)
	repaired := fmt.Sprintf(`REPAIRED mailbox_id=%d account_id=%d "Drifted" unseen_count 3 -> 1`, drifted.ID, accountID)

	out := runMailboxRepairUnseen(t, ctx, account.Email, "--batch-size", "1")
	require.Contains(t, out, wouldRepair)
	require.NotContains(t, out, fmt.Sprintf("mailbox_id=%d ", right.ID), "Right is counted right")
	require.Contains(t, out, fmt.Sprintf("resume with --start-after %d", drifted.ID), "each batch prints where to resume")
	require.Contains(t, out, "2 mailbox(es) with a wrong unseen_count, off by 3 in total")
	require.Contains(t, out, fmt.Sprintf(`WOULD REPAIR mailbox_id=%d account_id=%d "Stateless" unseen_count 0 -> 1`, stateless.ID, accountID))
	require.Equal(t, int64(3), cached(drifted.ID), "a dry run changes nothing")
	require.Equal(t, int64(0), cached(stateless.ID), "a dry run changes nothing")

	out = runMailboxRepairUnseen(t, ctx, account.Email, "--apply")
	require.Contains(t, out, repaired)
	require.Equal(t, int64(1), cached(drifted.ID))
	require.Equal(t, int64(1), cached(right.ID))
	require.Contains(t, out, fmt.Sprintf(`REPAIRED mailbox_id=%d account_id=%d "Stateless" unseen_count 0 -> 1`, stateless.ID, accountID))
	require.Equal(t, int64(1), cached(stateless.ID))

	out = runMailboxRepairUnseen(t, ctx, account.Email)
	require.Contains(t, out, "0 mailbox(es) with a wrong unseen_count")
}

// runMailboxRepairUnseen runs "sora-admin mailbox repair-unseen" for one account against
// the test database and returns what it printed.
func runMailboxRepairUnseen(t *testing.T, ctx context.Context, email string, flags ...string) string {
	t.Helper()
	previousConfig, previousArgs := globalConfig, os.Args
	t.Cleanup(func() { globalConfig, os.Args = previousConfig, previousArgs })
	name := os.Getenv("SORA_TEST_DB_NAME")
	if name == "" {
		name = "sora_test_db"
	}
	globalConfig.Database = config.DatabaseConfig{Write: &config.DatabaseEndpointConfig{
		Hosts: []string{"localhost"}, Port: "5432", User: "postgres", Name: name,
	}}
	os.Args = append([]string{"sora-admin", "mailbox", "repair-unseen", "--email", email}, flags...)
	out := captureStdout(t, func() error {
		handleMailboxRepairUnseen(ctx)
		return nil
	})
	t.Logf("%s\n%s", strings.Join(os.Args[2:], " "), out)
	return out
}
