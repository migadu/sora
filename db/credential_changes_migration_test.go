package db

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCredentialChangesMigrationLifecycle(t *testing.T) {
	d := setupTestDatabaseWithSuffix(t, "_feed_migration")
	defer d.Close()
	ctx := context.Background()
	up, err := os.ReadFile("migrations/000069_credential_changes.up.sql")
	require.NoError(t, err)
	down, err := os.ReadFile("migrations/000069_credential_changes.down.sql")
	require.NoError(t, err)
	accountID, email := credentialChangesAccount(t, d, "migration")
	apply := func(sql []byte) { _, err := d.GetWritePool().Exec(ctx, string(sql)); require.NoError(t, err) }
	// Repeated application must not duplicate trigger installation or events.
	apply(up)
	apply(up)
	var triggers, deferred int
	require.NoError(t, d.GetWritePool().QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tgdeferrable AND tginitdeferred) FROM pg_trigger WHERE tgname IN ('trigger_credentials_changed','trigger_credentials_removed','trigger_accounts_out_of_service','trigger_accounts_removed')`).Scan(&triggers, &deferred))
	require.Equal(t, 4, triggers)
	require.Equal(t, 4, deferred)
	count := func() int {
		var n int
		require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT count(*) FROM credential_changes WHERE account_id=$1", accountID).Scan(&n))
		return n
	}
	tx, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, "UPDATE credentials SET password='migration-new' WHERE address=$1", email)
	require.NoError(t, err)
	var inTx int
	require.NoError(t, tx.QueryRow(ctx, "SELECT count(*) FROM credential_changes WHERE account_id=$1", accountID).Scan(&inTx))
	require.Zero(t, inTx, "constraint triggers remain deferred by default")
	_, err = tx.Exec(ctx, "SET CONSTRAINTS ALL IMMEDIATE")
	require.NoError(t, err)
	require.NoError(t, tx.QueryRow(ctx, "SELECT count(*) FROM credential_changes WHERE account_id=$1", accountID).Scan(&inTx))
	require.Equal(t, 1, inTx, "explicit early execution records exactly one event")
	require.Zero(t, count(), "uncommitted early events remain invisible")
	require.NoError(t, tx.Rollback(ctx))
	require.Zero(t, count(), "rollback removes the early event atomically")
	_, err = d.GetWritePool().Exec(ctx, "UPDATE credentials SET password='migration-committed' WHERE address=$1", email)
	require.NoError(t, err)
	require.Equal(t, 1, count())
	apply(down)
	apply(down)
	var absent bool
	require.NoError(t, d.GetWritePool().QueryRow(ctx, "SELECT to_regclass('public.credential_changes') IS NULL AND to_regprocedure('record_credential_change()') IS NULL").Scan(&absent))
	require.True(t, absent)
	apply(up)
	apply(up)
	_, err = d.GetWritePool().Exec(ctx, "UPDATE credentials SET password='migration-recreated' WHERE address=$1", email)
	require.NoError(t, err)
	require.Equal(t, 1, count(), "recreated feed records one event without duplicate triggers")
}

// A database whose triggers were installed out-of-band must migrate without any lock on
// accounts or credentials: every login reads credentials, so a queued lock there stalls them.
func TestCredentialChangesMigrationPreparedTakesNoTableLocks(t *testing.T) {
	d := setupTestDatabaseWithSuffix(t, "_feed_migration")
	defer d.Close()
	ctx := context.Background()
	up, err := os.ReadFile("migrations/000069_credential_changes.up.sql")
	require.NoError(t, err)
	_, err = d.GetWritePool().Exec(ctx, string(up))
	require.NoError(t, err)

	conn, err := d.GetWritePool().Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	locker, err := d.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	_, err = locker.Exec(ctx, "LOCK TABLE accounts, credentials, credential_changes IN ACCESS EXCLUSIVE MODE")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SET lock_timeout = '200ms'")
	require.NoError(t, err)
	_, err = conn.Exec(ctx, string(up))
	_, _ = conn.Exec(ctx, "RESET lock_timeout")
	require.NoError(t, locker.Rollback(ctx))
	require.NoError(t, err, "the prepared migration must only inspect catalogs, even with the tables exclusively locked")
}

// A same-named trigger that does not call record_credential_change is not a prepared one.
func TestCredentialChangesMigrationReplacesForeignTrigger(t *testing.T) {
	d := setupTestDatabaseWithSuffix(t, "_feed_migration")
	defer d.Close()
	ctx := context.Background()
	up, err := os.ReadFile("migrations/000069_credential_changes.up.sql")
	require.NoError(t, err)
	pool := d.GetWritePool()
	_, err = pool.Exec(ctx, string(up))
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `CREATE OR REPLACE FUNCTION foreign_credential_trigger() RETURNS TRIGGER AS $$ BEGIN RETURN NULL; END; $$ LANGUAGE plpgsql;
		DROP TRIGGER trigger_accounts_removed ON accounts;
		CREATE CONSTRAINT TRIGGER trigger_accounts_removed AFTER DELETE ON accounts
			DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION foreign_credential_trigger()`)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DROP FUNCTION IF EXISTS foreign_credential_trigger() CASCADE") })

	_, err = pool.Exec(ctx, string(up))
	require.NoError(t, err)
	var ours bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT tgfoid = 'record_credential_change()'::regprocedure
		FROM pg_trigger WHERE tgrelid = 'accounts'::regclass AND tgname = 'trigger_accounts_removed'`).Scan(&ours))
	require.True(t, ours)
}
