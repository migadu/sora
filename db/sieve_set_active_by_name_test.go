package db

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// SetScriptActiveByName (sora-admin sieve activate) and SetScriptActive (ManageSieve
// SETACTIVE, the User API activate route) may activate the same script at the same
// time. SetScriptActive locks the active script's row (deactivating it), then the
// target's. When SetScriptActiveByName locked the target first and then waited for
// the active row, each transaction held the row the other needed: PostgreSQL broke
// the deadlock by aborting one of them (40P01).
func TestSetScriptActiveByName_LocksInSetScriptActiveOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	database := setupTestDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	accountID := createTestAccountForSieve(t, database, ctx)

	var target *SieveScript
	require.NoError(t, inSieveTx(t, database, ctx, func(tx pgx.Tx) error {
		active, err := database.CreateScript(ctx, tx, accountID, "active", "keep;")
		if err != nil {
			return err
		}
		if err := database.SetScriptActive(ctx, tx, active.ID, accountID, true); err != nil {
			return err
		}
		target, err = database.CreateScript(ctx, tx, accountID, "target", "keep;")
		return err
	}))

	// The activation by ID has run its first statement: it holds the active row.
	byID, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer byID.Rollback(context.Background())
	_, err = byID.Exec(ctx, "UPDATE sieve_scripts SET active = false WHERE account_id = $1 AND active = true", accountID)
	require.NoError(t, err)

	pidCh := make(chan uint32, 1)
	byNameErr := make(chan error, 1)
	go func() {
		tx, err := database.GetWritePool().Begin(ctx)
		if err != nil {
			byNameErr <- err
			return
		}
		defer tx.Rollback(context.Background())
		var pid uint32
		if err := tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
			byNameErr <- err
			return
		}
		pidCh <- pid
		if err := database.SetScriptActiveByName(ctx, tx, accountID, "target", true); err != nil {
			byNameErr <- err
			return
		}
		byNameErr <- tx.Commit(ctx)
	}()

	var pid uint32
	select {
	case pid = <-pidCh:
	case err := <-byNameErr:
		t.Fatalf("activation by name failed to start: %v", err)
	}
	for {
		var waitType *string
		require.NoError(t, database.GetWritePool().QueryRow(ctx,
			"SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1", pid).Scan(&waitType))
		if waitType != nil && *waitType == "Lock" {
			break
		}
		select {
		case err := <-byNameErr:
			t.Fatalf("activation by name finished while the active row was locked: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
	}

	// The activation by ID runs its second statement and commits.
	_, err = byID.Exec(ctx, "UPDATE sieve_scripts SET active = true, updated_at = now() WHERE id = $1 AND account_id = $2", target.ID, accountID)
	require.NoError(t, err, "activation by ID")
	require.NoError(t, byID.Commit(ctx), "activation by ID")
	require.NoError(t, <-byNameErr, "activation by name")

	var active string
	require.NoError(t, database.GetWritePool().QueryRow(ctx,
		"SELECT name FROM sieve_scripts WHERE account_id = $1 AND active", accountID).Scan(&active))
	require.Equal(t, "target", active)
}
