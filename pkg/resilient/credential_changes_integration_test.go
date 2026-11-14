//go:build integration

package resilient

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/require"
)

// Each read of credential_changes starts from the clock of the previous read less a
// fixed window. A replica that has not replayed a change yet still answers with its own
// clock, so once its lag exceeds the window the next read starts past the change and no
// read of that node ever sees it: the old password keeps working from that node's caches.
// The read must go to the primary even when the caller has not pinned it.
func TestGetCredentialChangesSinceWithRetry_UsesPrimary(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	primary := newTestPool(t, cfg, nil)
	schema := fmt.Sprintf("credchanges_replica_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	_, err := primary.Exec(ctx, "CREATE SCHEMA "+quotedSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := primary.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE")
		require.NoError(t, err)
	})
	// The replica's copy of the table: it has not replayed the change below yet.
	_, err = primary.Exec(ctx, "CREATE TABLE "+quotedSchema+".credential_changes (LIKE public.credential_changes INCLUDING ALL)")
	require.NoError(t, err)

	replicaCfg := primary.Config().Copy()
	replicaCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET search_path TO "+quotedSchema+", public")
		return err
	}
	replica, err := pgxpool.NewWithConfig(ctx, replicaCfg)
	require.NoError(t, err)
	t.Cleanup(replica.Close)
	require.NoError(t, replica.Ping(ctx))

	rdb := newTestResilientDatabase(cfg, primary)
	readPool := &DatabasePool{database: &db.Database{WritePool: replica, ReadPool: replica}, host: "lagging-replica"}
	readPool.isHealthy.Store(true)
	rdb.failoverManager.readPools = []*DatabasePool{readPool}

	// An account id no account has, so the row is this test's alone.
	accountID := -time.Now().UnixNano()
	var changedAt time.Time
	err = primary.QueryRow(ctx, `
		INSERT INTO credential_changes (account_id, ends_sessions) VALUES ($1, true)
		RETURNING changed_at
	`, accountID).Scan(&changedAt)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = primary.Exec(context.Background(), "DELETE FROM credential_changes WHERE account_id = $1", accountID)
	})

	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{
		{"default context", ctx},
		{"replica selected by caller", context.WithValue(ctx, consts.UseMasterDBKey, false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changes, err := rdb.GetCredentialChangesSinceWithRetry(tc.ctx, changedAt.Add(-time.Second))
			require.NoError(t, err)
			require.True(t, slices.Contains(changes.Accounts, accountID),
				"a change committed on the primary is missing from the read: it came from the replica")
			require.True(t, slices.Contains(changes.Removed, accountID))
		})
	}
}
