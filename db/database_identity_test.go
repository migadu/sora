package db

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

func TestDatabaseIdentityPersistsAcrossConnectionsAndMigrationReapply(t *testing.T) {
	d := setupTestDatabaseWithSuffix(t, "_identity_persist")
	ctx := context.Background()
	identity, err := d.GetDatabaseIdentity(ctx)
	require.NoError(t, err)
	require.NotEqual(t, uuid.Nil.String(), identity)
	var wg sync.WaitGroup
	type result struct {
		identity string
		err      error
	}
	results := make(chan result, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := d.GetDatabaseIdentity(ctx)
			results <- result{got, err}
		}()
	}
	wg.Wait()
	close(results)
	for got := range results {
		require.NoError(t, got.err)
		require.Equal(t, identity, got.identity)
	}
	d.GetWritePool().Reset()
	got, err := d.GetDatabaseIdentity(ctx)
	require.NoError(t, err)
	require.Equal(t, identity, got)
	d.Close()

	// A new Database object and migration check stand in for process restart.
	d = setupTestDatabaseWithSuffix(t, "_identity_persist")
	defer d.Close()
	got, err = d.GetDatabaseIdentity(ctx)
	require.NoError(t, err)
	require.Equal(t, identity, got)
	up, err := os.ReadFile("migrations/000068_database_identity.up.sql")
	require.NoError(t, err)
	for range 2 {
		_, err = d.GetWritePool().Exec(ctx, string(up))
		require.NoError(t, err)
		got, err = d.GetDatabaseIdentity(ctx)
		require.NoError(t, err)
		require.Equal(t, identity, got, "idempotent Up must retain the logical identity")
	}
}

func TestDatabaseIdentityUsesPrimaryAndSeparatesIndependentDatabases(t *testing.T) {
	primary := setupTestDatabaseWithSuffix(t, "_identity_primary")
	defer primary.Close()
	other := setupTestDatabaseWithSuffix(t, "_identity_other")
	defer other.Close()
	ctx := context.Background()
	want, err := primary.GetDatabaseIdentity(ctx)
	require.NoError(t, err)
	wrong, err := other.GetDatabaseIdentity(ctx)
	require.NoError(t, err)
	require.NotEqual(t, want, wrong, "independently migrated databases need independent identities")
	view := &Database{WritePool: primary.GetWritePool(), ReadPool: other.GetWritePool()}
	for _, readCtx := range []context.Context{ctx, context.WithValue(ctx, consts.UseMasterDBKey, false), context.WithValue(ctx, consts.UseMasterDBKey, true)} {
		got, err := view.GetDatabaseIdentity(readCtx)
		require.NoError(t, err)
		require.Equal(t, want, got, "never identify the read replica instead of the primary")
	}

	// A different DSN search_path must not select another logical identity.
	_, err = primary.GetWritePool().Exec(ctx, `CREATE SCHEMA IF NOT EXISTS identity_shadow;
		DROP TABLE IF EXISTS identity_shadow.database_identity;
		CREATE TABLE identity_shadow.database_identity (singleton boolean, identity uuid);
		INSERT INTO identity_shadow.database_identity VALUES (TRUE, gen_random_uuid())`)
	require.NoError(t, err)
	defer func() {
		primary.GetWritePool().Exec(context.Background(), "DROP SCHEMA IF EXISTS identity_shadow CASCADE")
	}()
	cfg := primary.GetWritePool().Config()
	cfg.ConnConfig.RuntimeParams["search_path"] = "identity_shadow, public"
	shadow, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer shadow.Close()
	view.WritePool = shadow
	got, err := view.GetDatabaseIdentity(ctx)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestDatabaseIdentityFailsClosedWithoutValidSingleton(t *testing.T) {
	d := setupTestDatabaseWithSuffix(t, "_identity_invalid")
	defer d.Close()
	ctx := context.Background()
	up, err := os.ReadFile("migrations/000068_database_identity.up.sql")
	require.NoError(t, err)
	reset := func(t *testing.T) {
		_, err := d.GetWritePool().Exec(ctx, "DROP TABLE IF EXISTS public.database_identity")
		require.NoError(t, err)
		_, err = d.GetWritePool().Exec(ctx, string(up))
		require.NoError(t, err)
	}
	defer reset(t)
	for _, tc := range []struct{ name, sql string }{
		{"missing row", "DELETE FROM public.database_identity"},
		{"zero UUID", "UPDATE public.database_identity SET identity='00000000-0000-0000-0000-000000000000'"},
		{"malformed UUID", `ALTER TABLE public.database_identity ALTER COLUMN identity DROP DEFAULT;
			ALTER TABLE public.database_identity ALTER COLUMN identity TYPE text USING identity::text;
			UPDATE public.database_identity SET identity='not-a-uuid'`},
		{"null UUID", `ALTER TABLE public.database_identity ALTER COLUMN identity DROP NOT NULL;
			UPDATE public.database_identity SET identity=NULL`},
		{"false singleton", `ALTER TABLE public.database_identity DROP CONSTRAINT database_identity_singleton_check;
			UPDATE public.database_identity SET singleton=FALSE`},
		{"multiple rows", `ALTER TABLE public.database_identity DROP CONSTRAINT database_identity_pkey;
			INSERT INTO public.database_identity(singleton) VALUES(TRUE),(TRUE)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reset(t)
			_, err := d.GetDatabaseIdentity(ctx)
			require.NoError(t, err)
			_, err = d.GetWritePool().Exec(ctx, tc.sql)
			require.NoError(t, err)
			got, err := d.GetDatabaseIdentity(ctx)
			require.ErrorIs(t, err, ErrDatabaseIdentityUnavailable)
			require.Empty(t, got, "never reuse an earlier successful identity")
		})
	}
	reset(t)
	_, err = d.GetWritePool().Exec(ctx, "DROP TABLE public.database_identity")
	require.NoError(t, err)
	got, err := d.GetDatabaseIdentity(ctx)
	require.Error(t, err)
	require.Empty(t, got)
	reset(t)
}

func TestDatabaseIdentityMigrationDownUpRotatesAndCancellationFailsClosed(t *testing.T) {
	d := setupTestDatabaseWithSuffix(t, "_identity_rotate")
	defer d.Close()
	ctx := context.Background()
	before, err := d.GetDatabaseIdentity(ctx)
	require.NoError(t, err)
	up, err := os.ReadFile("migrations/000068_database_identity.up.sql")
	require.NoError(t, err)
	down, err := os.ReadFile("migrations/000068_database_identity.down.sql")
	require.NoError(t, err)
	for range 2 {
		_, err = d.GetWritePool().Exec(ctx, string(down))
		require.NoError(t, err)
	}
	_, err = d.GetDatabaseIdentity(ctx)
	require.Error(t, err)
	_, err = d.GetWritePool().Exec(ctx, string(up))
	require.NoError(t, err)
	after, err := d.GetDatabaseIdentity(ctx)
	require.NoError(t, err)
	require.NotEqual(t, before, after, "recreating the table starts a new destination namespace")
	versions, err := MigrationVersions()
	require.NoError(t, err)
	require.Contains(t, versions, uint(68))

	block, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer block.Rollback(ctx)
	_, err = block.Exec(ctx, "LOCK TABLE public.database_identity IN ACCESS EXCLUSIVE MODE")
	require.NoError(t, err)
	short, cancel := context.WithTimeout(ctx, 75*time.Millisecond)
	got, err := d.GetDatabaseIdentity(short)
	cancel()
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Empty(t, got, "a prior successful identity must not hide a failed primary read")
	require.NoError(t, block.Rollback(ctx))
	got, err = d.GetDatabaseIdentity(ctx)
	require.NoError(t, err)
	require.Equal(t, after, got)
}
