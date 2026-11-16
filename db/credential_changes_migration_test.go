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
