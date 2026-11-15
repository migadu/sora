package db

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// fillSieveScripts gives the account n scripts.
func fillSieveScripts(t *testing.T, database *Database, ctx context.Context, accountID int64, n int) {
	t.Helper()
	require.NoError(t, inSieveTx(t, database, ctx, func(tx pgx.Tx) error {
		for i := range n {
			if _, err := database.CreateScript(ctx, tx, accountID, fmt.Sprintf("fill-%03d", i), "keep;"); err != nil {
				return err
			}
		}
		return nil
	}))
}

func countSieveScripts(t *testing.T, database *Database, ctx context.Context, accountID int64) int {
	t.Helper()
	var n int
	require.NoError(t, database.GetWritePool().QueryRow(ctx,
		"SELECT COUNT(*) FROM sieve_scripts WHERE account_id = $1", accountID).Scan(&n))
	return n
}

// TestSieveScriptLimitHoldsWhileAnotherCreateIsOpen: the per-account script limit
// must hold when two creates of one account run at the same time. The count was
// read and compared without anything serialising the account, so a second create
// that started before the first committed saw the old count, passed, and both
// scripts were stored.
func TestSieveScriptLimitHoldsWhileAnotherCreateIsOpen(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	database := setupTestDatabase(t)
	ctx := context.Background()
	accountID := createTestAccountForSieve(t, database, ctx)
	fillSieveScripts(t, database, ctx, accountID, maxScriptsPerAccount-1)

	secondErr := writeWhileAnotherIsOpen(t, database,
		func(ctx context.Context, tx pgx.Tx) error {
			_, err := database.CreateScript(ctx, tx, accountID, "race-a", "keep;")
			return err
		},
		func(ctx context.Context, tx pgx.Tx) error {
			_, err := database.CreateScript(ctx, tx, accountID, "race-b", "keep;")
			return err
		})

	require.LessOrEqual(t, countSieveScripts(t, database, ctx, accountID), maxScriptsPerAccount,
		"scripts stored past the per-account limit")
	require.ErrorIs(t, secondErr, ErrSieveScriptLimitReached)
}

// TestSieveScriptLimitHoldsUnderConcurrentCreates is the issue's reproduction:
// many creates of one account, each with a different new name, at the same time.
// No more than the free slots may succeed or be stored.
func TestSieveScriptLimitHoldsUnderConcurrentCreates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	const writers = 20
	const free = 5
	// A connection per writer, so every transaction is open before any of them
	// creates.
	database := setupTestDatabaseWithMaxConns(t, writers+2)
	defer database.Close()
	ctx := context.Background()
	accountID := createTestAccountForSieve(t, database, ctx)
	fillSieveScripts(t, database, ctx, accountID, maxScriptsPerAccount-free)

	start := make(chan struct{})
	errs := make([]error, writers)
	var ready, wg sync.WaitGroup
	for i := range writers {
		ready.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := database.GetWritePool().Begin(ctx)
			ready.Done()
			if err != nil {
				errs[i] = err
				return
			}
			defer tx.Rollback(context.Background())
			<-start
			if _, err := database.CreateScript(ctx, tx, accountID, fmt.Sprintf("race-%02d", i), "keep;"); err != nil {
				errs[i] = err
				return
			}
			errs[i] = tx.Commit(ctx)
		}()
	}
	ready.Wait()
	close(start)
	wg.Wait()

	accepted := 0
	for i, err := range errs {
		if err == nil {
			accepted++
			continue
		}
		require.ErrorIs(t, err, ErrSieveScriptLimitReached, "writer %d", i)
	}
	require.Equal(t, free, accepted, "script creates accepted")
	require.Equal(t, maxScriptsPerAccount, countSieveScripts(t, database, ctx, accountID), "scripts stored")
}
