//go:build integration

package resilient

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/require"
)

// newIdentityTestDatabase creates an empty database, dropped when the test ends, that
// db.NewDatabaseFromConfig migrates; migration 000068 gives it an identity of its own.
// The test deletes and re-creates the primary's identity row, which must never happen
// to the shared test database: it would change the identity under other packages.
func newIdentityTestDatabase(t *testing.T, suffix string) *config.DatabaseConfig {
	t.Helper()
	cfg := testDatabaseConfig()
	cfg.Write.Name = fmt.Sprintf("%s_identity_%d_%s", cfg.Write.Name, time.Now().UnixNano(), suffix)
	maintenance := fmt.Sprintf("postgres://%s@%s:%s/postgres?sslmode=disable", cfg.Write.User, cfg.Write.Hosts[0], cfg.Write.Port)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, maintenance)
	if err != nil {
		t.Skipf("PostgreSQL not available: %v", err)
	}
	defer admin.Close(ctx)
	_, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{cfg.Write.Name}.Sanitize())
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		admin, err := pgx.Connect(ctx, maintenance)
		if err != nil {
			t.Errorf("connect to drop %s: %v", cfg.Write.Name, err)
			return
		}
		defer admin.Close(ctx)
		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{cfg.Write.Name}.Sanitize()+" WITH (FORCE)"); err != nil {
			t.Errorf("drop %s: %v", cfg.Write.Name, err)
		}
	})
	return cfg
}

func TestDatabaseIdentityWithRetryUsesPrimaryAcrossPoolFailover(t *testing.T) {
	ctx := context.Background()
	cfg := newIdentityTestDatabase(t, "primary")
	primary, err := db.NewDatabaseFromConfig(ctx, cfg, true)
	require.NoError(t, err)
	defer primary.Close()
	want, err := primary.GetDatabaseIdentity(ctx)
	require.NoError(t, err)
	otherCfg := newIdentityTestDatabase(t, "replica")
	other, err := db.NewDatabaseFromConfig(ctx, otherCfg, true)
	require.NoError(t, err)
	defer other.Close()
	wrong, err := other.GetDatabaseIdentity(ctx)
	require.NoError(t, err)
	require.NotEqual(t, want, wrong)

	rd := newTestResilientDatabase(cfg, primary.GetWritePool())
	readPool := &DatabasePool{database: other, host: "independent-read-database"}
	readPool.isHealthy.Store(true)
	rd.failoverManager.readPools = []*DatabasePool{readPool}
	got, err := rd.GetDatabaseIdentityWithRetry(ctx)
	require.NoError(t, err)
	require.Equal(t, want, got, "the read endpoint deliberately has a different valid identity")

	// A second pool for the SAME logical database models changing the selected
	// primary connection/host without manufacturing a per-pool identity.
	second, err := pgxpool.NewWithConfig(ctx, primary.GetWritePool().Config())
	require.NoError(t, err)
	defer second.Close()
	next := &DatabasePool{database: &db.Database{WritePool: second, ReadPool: second}, host: "replacement-primary-pool"}
	next.isHealthy.Store(true)
	rd.failoverManager.writePools = append(rd.failoverManager.writePools, next)
	rd.failoverManager.writePools[0].isHealthy.Store(false)
	got, err = rd.GetDatabaseIdentityWithRetry(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), rd.failoverManager.currentWriteIdx.Load())
	require.Equal(t, want, got)

	// A healthy read endpoint must not conceal a missing primary identity, and
	// an earlier successful lookup must not be returned from an in-memory cache.
	_, err = second.Exec(ctx, "DELETE FROM public.database_identity")
	require.NoError(t, err)
	got, err = rd.GetDatabaseIdentityWithRetry(ctx)
	require.ErrorIs(t, err, db.ErrDatabaseIdentityUnavailable)
	require.Empty(t, got)
	_, err = second.Exec(ctx, "INSERT INTO public.database_identity(singleton) VALUES(TRUE)")
	require.NoError(t, err)
	got, err = rd.GetDatabaseIdentityWithRetry(ctx)
	require.NoError(t, err)
	require.NotEqual(t, want, got, "a newly generated persisted identity must be read afresh")
	require.NotEqual(t, wrong, got)
}
