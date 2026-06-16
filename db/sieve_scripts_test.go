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

// createTestAccountForSieve creates a fresh account and returns its ID.
func createTestAccountForSieve(t *testing.T, database *Database, ctx context.Context) int64 {
	t.Helper()
	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)

	email := fmt.Sprintf("sieve_%d@example.com", time.Now().UnixNano())
	accountID, err := database.CreateAccount(ctx, tx, CreateAccountRequest{
		Email:     email,
		Password:  "password123",
		IsPrimary: true,
		HashType:  "bcrypt",
	})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return accountID
}

// inSieveTx runs fn inside a committed write transaction.
func inSieveTx(t *testing.T, database *Database, ctx context.Context, fn func(tx pgx.Tx) error) error {
	t.Helper()
	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// TestRenameScript verifies the atomic single-statement RenameScript:
// success preserves active state/content, missing source -> ErrDBNotFound,
// name collision -> ErrDBUniqueViolation, and self-rename is a no-op success.
func TestRenameScript(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	database := setupTestDatabase(t)
	defer database.Close()
	ctx := context.Background()

	accountID := createTestAccountForSieve(t, database, ctx)

	// Create an active script and an unrelated second script.
	require.NoError(t, inSieveTx(t, database, ctx, func(tx pgx.Tx) error {
		s, err := database.CreateScript(ctx, tx, accountID, "original", "keep;")
		if err != nil {
			return err
		}
		return database.SetScriptActive(ctx, tx, s.ID, accountID, true)
	}))
	require.NoError(t, inSieveTx(t, database, ctx, func(tx pgx.Tx) error {
		_, err := database.CreateScript(ctx, tx, accountID, "other", "discard;")
		return err
	}))

	t.Run("success preserves active state and content", func(t *testing.T) {
		err := inSieveTx(t, database, ctx, func(tx pgx.Tx) error {
			return database.RenameScript(ctx, tx, accountID, "original", "renamed")
		})
		require.NoError(t, err)

		// Old name is gone.
		_, err = database.GetScriptByName(ctx, "original", accountID)
		assert.ErrorIs(t, err, consts.ErrDBNotFound)

		// New name exists with content + active preserved.
		renamed, err := database.GetScriptByName(ctx, "renamed", accountID)
		require.NoError(t, err)
		assert.Equal(t, "keep;", renamed.Script)
		assert.True(t, renamed.Active, "renamed script must remain active (RFC 5804 §2.11.1)")

		// It is still the account's single active script.
		active, err := database.GetActiveScript(ctx, accountID)
		require.NoError(t, err)
		assert.Equal(t, "renamed", active.Name)
	})

	t.Run("missing source returns ErrDBNotFound", func(t *testing.T) {
		err := inSieveTx(t, database, ctx, func(tx pgx.Tx) error {
			return database.RenameScript(ctx, tx, accountID, "does-not-exist", "whatever")
		})
		assert.ErrorIs(t, err, consts.ErrDBNotFound)
	})

	t.Run("name collision returns ErrDBUniqueViolation", func(t *testing.T) {
		err := inSieveTx(t, database, ctx, func(tx pgx.Tx) error {
			return database.RenameScript(ctx, tx, accountID, "renamed", "other")
		})
		assert.ErrorIs(t, err, consts.ErrDBUniqueViolation)

		// Source untouched after the failed rename.
		src, err := database.GetScriptByName(ctx, "renamed", accountID)
		require.NoError(t, err)
		assert.True(t, src.Active)
	})

	t.Run("self-rename is a no-op success", func(t *testing.T) {
		err := inSieveTx(t, database, ctx, func(tx pgx.Tx) error {
			return database.RenameScript(ctx, tx, accountID, "renamed", "renamed")
		})
		require.NoError(t, err)

		s, err := database.GetScriptByName(ctx, "renamed", accountID)
		require.NoError(t, err)
		assert.True(t, s.Active)
		assert.Equal(t, "keep;", s.Script)
	})

	// Isolation: another account's identically named script is independent.
	t.Run("scoped per account", func(t *testing.T) {
		otherAccount := createTestAccountForSieve(t, database, ctx)
		require.NoError(t, inSieveTx(t, database, ctx, func(tx pgx.Tx) error {
			_, err := database.CreateScript(ctx, tx, otherAccount, "renamed", "stop;")
			return err
		}))

		// Renaming the other account's "renamed" must not collide with the first account.
		err := inSieveTx(t, database, ctx, func(tx pgx.Tx) error {
			return database.RenameScript(ctx, tx, otherAccount, "renamed", "moved")
		})
		require.NoError(t, err)

		// First account's "renamed" is still intact.
		_, err = database.GetScriptByName(ctx, "renamed", accountID)
		assert.NoError(t, err)
	})
}
