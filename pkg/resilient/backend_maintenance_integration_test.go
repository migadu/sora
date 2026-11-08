//go:build integration

package resilient

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/require"
)

// A read-pool failover can move backwards in replication history. If that reopens
// the admission gate, --wait can still see the last refusing, zero-session report
// on the primary until the next report commits. The lookup must use the primary
// even when the caller has not pinned it, or explicitly selected replica reads.
func TestGetMaintenanceRefusalWithRetry_UsesPrimary(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	primary := newTestPool(t, cfg, nil)
	schema := fmt.Sprintf("maintenance_replica_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	_, err := primary.Exec(ctx, "CREATE SCHEMA "+quotedSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := primary.Exec(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE")
		require.NoError(t, err)
	})
	_, err = primary.Exec(ctx, "CREATE TABLE "+quotedSchema+".backend_maintenance (LIKE public.backend_maintenance INCLUDING ALL)")
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

	instance := schema + "-node"
	host := schema + ".example.com"
	t.Cleanup(func() {
		_, err := primary.Exec(ctx, "DELETE FROM backend_maintenance WHERE host = $1", host)
		require.NoError(t, err)
	})
	var began time.Time
	err = primary.QueryRow(ctx, `
		INSERT INTO backend_maintenance (host, instance_id)
		VALUES ($1, $2) RETURNING created_at
	`, host, instance).Scan(&began)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{
		{"default context", ctx},
		{"replica selected by caller", context.WithValue(ctx, consts.UseMasterDBKey, false)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// This replica predates maintenance; a successful empty read must not
			// be mistaken for permission to reopen an already refusing backend.
			since, err := rdb.GetMaintenanceRefusalWithRetry(tc.ctx, instance, 0)
			require.NoError(t, err)
			require.NotNil(t, since, "a lagging replica must not end active maintenance")
			require.True(t, since.Equal(began), "refusal must identify the primary's maintenance")
		})
	}

	// The reverse lag must not keep refusing sessions after maintenance ends.
	_, err = primary.Exec(ctx, "INSERT INTO "+quotedSchema+".backend_maintenance SELECT * FROM public.backend_maintenance WHERE host = $1", host)
	require.NoError(t, err)
	_, err = primary.Exec(ctx, "DELETE FROM backend_maintenance WHERE host = $1", host)
	require.NoError(t, err)
	since, err := rdb.GetMaintenanceRefusalWithRetry(ctx, instance, 0)
	require.NoError(t, err)
	require.Nil(t, since, "a lagging replica must not preserve ended maintenance")
}
