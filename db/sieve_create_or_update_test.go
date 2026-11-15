package db

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
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
