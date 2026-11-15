package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createOrUpdateScript(t *testing.T, database *Database, ctx context.Context, accountID int64, name, script string) (*SieveScript, bool, error) {
	t.Helper()
	var (
		stored  *SieveScript
		updated bool
	)
	err := inSieveTx(t, database, ctx, func(tx pgx.Tx) error {
		var err error
		stored, updated, err = database.CreateOrUpdateScript(ctx, tx, accountID, name, script)
		return err
	})
	return stored, updated, err
}

func TestCreateOrUpdateScript(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	t.Run("a new name is created inactive", func(t *testing.T) {
		accountID := createTestAccountForSieve(t, database, ctx)
		s, updated, err := createOrUpdateScript(t, database, ctx, accountID, "filters", "keep;")
		require.NoError(t, err)
		assert.False(t, updated)
		assert.Equal(t, "filters", s.Name)
		assert.Equal(t, "keep;", s.Script)
		assert.False(t, s.Active)
	})

	t.Run("an existing name is replaced and keeps its active state", func(t *testing.T) {
		accountID := createTestAccountForSieve(t, database, ctx)
		first, _, err := createOrUpdateScript(t, database, ctx, accountID, "filters", "keep;")
		require.NoError(t, err)
		require.NoError(t, inSieveTx(t, database, ctx, func(tx pgx.Tx) error {
			return database.SetScriptActive(ctx, tx, first.ID, accountID, true)
		}))

		s, updated, err := createOrUpdateScript(t, database, ctx, accountID, "filters", "discard;")
		require.NoError(t, err)
		assert.True(t, updated)
		assert.Equal(t, first.ID, s.ID)
		assert.Equal(t, "discard;", s.Script)
		assert.True(t, s.Active)
		assert.Equal(t, 1, countSieveScripts(t, database, ctx, accountID))
	})

	t.Run("at the limit an existing name is replaced and a new one refused", func(t *testing.T) {
		accountID := createTestAccountForSieve(t, database, ctx)
		fillSieveScripts(t, database, ctx, accountID, maxScriptsPerAccount)

		_, updated, err := createOrUpdateScript(t, database, ctx, accountID, "fill-000", "discard;")
		require.NoError(t, err)
		assert.True(t, updated)

		_, _, err = createOrUpdateScript(t, database, ctx, accountID, "one-more", "keep;")
		require.ErrorIs(t, err, ErrSieveScriptLimitReached)
		assert.Equal(t, maxScriptsPerAccount, countSieveScripts(t, database, ctx, accountID))
	})

	t.Run("an unstorable name or script is refused", func(t *testing.T) {
		accountID := createTestAccountForSieve(t, database, ctx)
		_, _, err := createOrUpdateScript(t, database, ctx, accountID, "a\x00b", "keep;")
		assert.ErrorIs(t, err, ErrSieveScriptNotStorable)
		_, _, err = createOrUpdateScript(t, database, ctx, accountID, "filters", "# \xff\nkeep;")
		assert.ErrorIs(t, err, ErrSieveScriptNotStorable)
	})
}

// A rename to the name, which does not take the account's script lock, commits
// between the update finding no script and the insert: the insert must not fail on
// UNIQUE (account_id, name), the renamed script is the one replaced.
func TestCreateOrUpdateScriptWhileRenameToNameIsOpen(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()
	accountID := createTestAccountForSieve(t, database, ctx)
	_, _, err := createOrUpdateScript(t, database, ctx, accountID, "old", "keep;")
	require.NoError(t, err)

	var updated bool
	err = writeWhileAnotherIsOpen(t, database,
		func(ctx context.Context, tx pgx.Tx) error {
			return database.RenameScript(ctx, tx, accountID, "old", "filters")
		},
		func(ctx context.Context, tx pgx.Tx) error {
			var err error
			_, updated, err = database.CreateOrUpdateScript(ctx, tx, accountID, "filters", "discard;")
			return err
		})
	require.NoError(t, err)
	assert.True(t, updated)

	s, err := database.GetScriptByName(ctx, "filters", accountID)
	require.NoError(t, err)
	assert.Equal(t, "discard;", s.Script)
	assert.Equal(t, 1, countSieveScripts(t, database, ctx, accountID))
}

// TestCreateOrUpdateScriptAtLimitWhileRenameToNameIsOpen: when the account is
// already at maxScriptsPerAccount and RenameScript or UpdateScript is renaming an
// existing script into name, CreateOrUpdateScript(name) replaces that script (adding
// zero scripts) and must not fail checkScriptLimit with ErrSieveScriptLimitReached.
func TestCreateOrUpdateScriptAtLimitWhileRenameToNameIsOpen(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	t.Run("RenameScript", func(t *testing.T) {
		accountID := createTestAccountForSieve(t, database, ctx)
		fillSieveScripts(t, database, ctx, accountID, maxScriptsPerAccount)

		var updated bool
		err := writeWhileAnotherIsOpen(t, database,
			func(ctx context.Context, tx pgx.Tx) error {
				return database.RenameScript(ctx, tx, accountID, "fill-000", "filters")
			},
			func(ctx context.Context, tx pgx.Tx) error {
				var err error
				_, updated, err = database.CreateOrUpdateScript(ctx, tx, accountID, "filters", "discard;")
				return err
			})
		require.NoError(t, err)
		assert.True(t, updated)

		_, err = database.GetScriptByName(ctx, "fill-000", accountID)
		assert.ErrorIs(t, err, consts.ErrDBNotFound)

		s, err := database.GetScriptByName(ctx, "filters", accountID)
		require.NoError(t, err)
		assert.Equal(t, "discard;", s.Script)
		assert.Equal(t, maxScriptsPerAccount, countSieveScripts(t, database, ctx, accountID))
	})

	t.Run("UpdateScript", func(t *testing.T) {
		accountID := createTestAccountForSieve(t, database, ctx)
		fillSieveScripts(t, database, ctx, accountID, maxScriptsPerAccount)

		target, err := database.GetScriptByName(ctx, "fill-000", accountID)
		require.NoError(t, err)

		var updated bool
		err = writeWhileAnotherIsOpen(t, database,
			func(ctx context.Context, tx pgx.Tx) error {
				_, err := database.UpdateScript(ctx, tx, target.ID, accountID, "filters", "keep;")
				return err
			},
			func(ctx context.Context, tx pgx.Tx) error {
				var err error
				_, updated, err = database.CreateOrUpdateScript(ctx, tx, accountID, "filters", "discard;")
				return err
			})
		require.NoError(t, err)
		assert.True(t, updated)

		_, err = database.GetScriptByName(ctx, "fill-000", accountID)
		assert.ErrorIs(t, err, consts.ErrDBNotFound)

		s, err := database.GetScriptByName(ctx, "filters", accountID)
		require.NoError(t, err)
		assert.Equal(t, target.ID, s.ID)
		assert.Equal(t, "discard;", s.Script)
		assert.Equal(t, maxScriptsPerAccount, countSieveScripts(t, database, ctx, accountID))
	})
}

// TestCreateOrUpdateScriptConflictDeletedBeforeRetryUpdate: if INSERT ... ON CONFLICT
// (account_id, name) DO NOTHING sees a conflicting row (pgx.ErrNoRows) and that row
// disappears before updateScriptByName runs (e.g. a concurrent DeleteScript),
// CreateOrUpdateScript must loop and insert the script rather than leaking pgx.ErrNoRows.
func TestCreateOrUpdateScriptConflictDeletedBeforeRetryUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	accountID := createTestAccountForSieve(t, database, ctx)
	pool := database.GetWritePool()

	stateTable := fmt.Sprintf("sieve_upsert_once_%d", accountID)
	trigFn := fmt.Sprintf("sieve_upsert_vanish_fn_%d", accountID)
	trigName := fmt.Sprintf("sieve_upsert_vanish_trg_%d", accountID)

	_, err := pool.Exec(ctx, fmt.Sprintf(`
		CREATE TABLE %s (armed bool);
		INSERT INTO %s VALUES (true);
		CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		DECLARE
			was_armed bool;
		BEGIN
			DELETE FROM %s RETURNING armed INTO was_armed;
			IF FOUND THEN
				DELETE FROM sieve_scripts WHERE id = OLD.id;
				RETURN NULL;
			END IF;
			RETURN NEW;
		END;
		$$;
		CREATE TRIGGER %s BEFORE UPDATE ON sieve_scripts
		FOR EACH ROW WHEN (OLD.account_id = %d)
		EXECUTE FUNCTION %s();
	`, stateTable, stateTable, trigFn, stateTable, trigName, accountID, trigFn))
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanCtx := context.Background()
		pool.Exec(cleanCtx, fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON sieve_scripts", trigName))
		pool.Exec(cleanCtx, fmt.Sprintf("DROP FUNCTION IF EXISTS %s()", trigFn))
		pool.Exec(cleanCtx, fmt.Sprintf("DROP TABLE IF EXISTS %s", stateTable))
	})

	// Hold an uncommitted row on (accountID, "filters") without taking lockScriptCreates
	// so CreateOrUpdateScript misses it in updateScriptByName and hits ON CONFLICT DO NOTHING.
	txA, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer txA.Rollback(context.Background())
	_, err = txA.Exec(ctx, `
		INSERT INTO sieve_scripts (account_id, name, script, active)
		VALUES ($1, 'filters', 'keep;', false)
	`, accountID)
	require.NoError(t, err)

	var (
		stored  *SieveScript
		updated bool
	)
	pidCh := make(chan uint32, 1)
	errCh := make(chan error, 1)
	go func() {
		txB, err := pool.Begin(ctx)
		if err != nil {
			errCh <- err
			return
		}
		defer txB.Rollback(context.Background())
		var pid uint32
		if err := txB.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
			errCh <- err
			return
		}
		pidCh <- pid
		stored, updated, err = database.CreateOrUpdateScript(ctx, txB, accountID, "filters", "discard;")
		if err != nil {
			errCh <- err
			return
		}
		errCh <- txB.Commit(ctx)
	}()

	var pid uint32
	select {
	case pid = <-pidCh:
	case err := <-errCh:
		t.Fatalf("second transaction failed to start: %v", err)
	}

	for {
		var waitType *string
		require.NoError(t, pool.QueryRow(ctx,
			"SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1", pid).Scan(&waitType))
		if waitType != nil && *waitType == "Lock" {
			break
		}
		select {
		case err := <-errCh:
			t.Fatalf("CreateOrUpdateScript returned before waiting on ON CONFLICT: %v", err)
		case <-ctx.Done():
			t.Fatal("timed out waiting for CreateOrUpdateScript to block on ON CONFLICT")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	require.NoError(t, txA.Commit(ctx))
	require.NoError(t, <-errCh)
	assert.False(t, updated)
	require.NotNil(t, stored)
	assert.Equal(t, "discard;", stored.Script)

	s, err := database.GetScriptByName(ctx, "filters", accountID)
	require.NoError(t, err)
	assert.Equal(t, "discard;", s.Script)
	assert.Equal(t, 1, countSieveScripts(t, database, ctx, accountID))
}
