package db

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

// The purge request mark: set by RequestAccountPurge, listed by ListAccountsForPurge when
// due, backed off by RecordAccountPurgeFailure, cleared by RestoreAccount.

func purgeMark(t *testing.T, db *Database, accountID int64) (deleted, marked bool, requestedAt *time.Time, attempts int, next *time.Time) {
	t.Helper()
	require.NoError(t, db.GetWritePool().QueryRow(context.Background(), `
		SELECT deleted_at IS NOT NULL, purge_requested_at IS NOT NULL, purge_requested_at, purge_attempts, purge_next_attempt_at
		FROM accounts WHERE id = $1`, accountID).Scan(&deleted, &marked, &requestedAt, &attempts, &next))
	return
}

func inTx(t *testing.T, db *Database, fn func(tx pgx.Tx)) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	fn(tx)
	require.NoError(t, tx.Commit(ctx))
}

func listed(t *testing.T, db *Database, accountID int64) bool {
	t.Helper()
	ids, err := db.ListAccountsForPurge(context.Background(), 1000)
	require.NoError(t, err)
	for _, id := range ids {
		if id == accountID {
			return true
		}
	}
	return false
}

func TestRequestAccountPurge_MarksAndDisables(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db, accountID, email, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	var id int64
	var requestedAt time.Time
	inTx(t, db, func(tx pgx.Tx) {
		var err error
		id, requestedAt, err = db.RequestAccountPurge(ctx, tx, email)
		require.NoError(t, err)
	})
	require.Equal(t, accountID, id)
	require.False(t, requestedAt.IsZero())

	deleted, marked, storedAt, attempts, next := purgeMark(t, db, accountID)
	require.True(t, deleted, "a purge request takes the account out of service")
	require.True(t, marked)
	require.True(t, storedAt.Equal(requestedAt))
	require.Equal(t, 0, attempts)
	require.Nil(t, next)
	require.True(t, listed(t, db, accountID), "a marked, out-of-service account is due")

	// Out of service means no login and no delivery.
	_, err := db.GetActiveAccountIDByAddress(ctx, email)
	require.ErrorIs(t, err, consts.ErrUserNotFound)
}

func TestRequestAccountPurge_RepeatKeepsFirstTimeAndClearsBackoff(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db, accountID, email, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	var first time.Time
	inTx(t, db, func(tx pgx.Tx) {
		var err error
		_, first, err = db.RequestAccountPurge(ctx, tx, email)
		require.NoError(t, err)
	})
	inTx(t, db, func(tx pgx.Tx) {
		next, err := db.RecordAccountPurgeFailure(ctx, tx, accountID, time.Minute, time.Hour)
		require.NoError(t, err)
		require.True(t, next.After(time.Now().Add(30*time.Second)), "first backoff is about one minute, got %v", next)
	})
	require.False(t, listed(t, db, accountID), "a backed-off account is not due")

	inTx(t, db, func(tx pgx.Tx) {
		_, again, err := db.RequestAccountPurge(ctx, tx, email)
		require.NoError(t, err)
		require.True(t, again.Equal(first), "a repeated request keeps the first request time")
	})
	_, _, _, attempts, next := purgeMark(t, db, accountID)
	require.Equal(t, 0, attempts, "a new request clears the attempt count")
	require.Nil(t, next, "a new request clears the backoff")
	require.True(t, listed(t, db, accountID))
}

func TestRequestAccountPurge_UnknownAddress(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	_, _, err = db.RequestAccountPurge(ctx, tx, "nobody-purge@example.com")
	require.ErrorIs(t, err, consts.ErrUserNotFound)
}

func TestRecordAccountPurgeFailure_DoublesAndCaps(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db, accountID, email, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	inTx(t, db, func(tx pgx.Tx) {
		_, _, err := db.RequestAccountPurge(ctx, tx, email)
		require.NoError(t, err)
	})

	// base 1m, cap 3m: 1m, 2m, 3m, 3m
	want := []time.Duration{time.Minute, 2 * time.Minute, 3 * time.Minute, 3 * time.Minute}
	for i, delay := range want {
		inTx(t, db, func(tx pgx.Tx) {
			next, err := db.RecordAccountPurgeFailure(ctx, tx, accountID, time.Minute, 3*time.Minute)
			require.NoError(t, err)
			require.WithinDuration(t, time.Now().Add(delay), next, 15*time.Second, "attempt %d", i+1)
		})
	}
	_, _, _, attempts, _ := purgeMark(t, db, accountID)
	require.Equal(t, 4, attempts)
}

func TestRecordAccountPurgeFailure_UnmarkedAccountUntouched(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db, accountID, _, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	inTx(t, db, func(tx pgx.Tx) {
		next, err := db.RecordAccountPurgeFailure(ctx, tx, accountID, time.Minute, time.Hour)
		require.NoError(t, err)
		require.True(t, next.IsZero())
	})
	_, _, _, attempts, next := purgeMark(t, db, accountID)
	require.Equal(t, 0, attempts)
	require.Nil(t, next)
}

func TestRestoreAccount_ClearsPurgeRequest(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db, accountID, email, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	inTx(t, db, func(tx pgx.Tx) {
		_, _, err := db.RequestAccountPurge(ctx, tx, email)
		require.NoError(t, err)
		_, err = db.RecordAccountPurgeFailure(ctx, tx, accountID, time.Minute, time.Hour)
		require.NoError(t, err)
	})
	inTx(t, db, func(tx pgx.Tx) {
		require.NoError(t, db.RestoreAccount(ctx, tx, email))
	})

	deleted, marked, _, attempts, next := purgeMark(t, db, accountID)
	require.False(t, deleted)
	require.False(t, marked, "restore must clear the purge request")
	require.Equal(t, 0, attempts)
	require.Nil(t, next)
	require.False(t, listed(t, db, accountID))

	details, err := db.GetAccountDetails(ctx, email)
	require.NoError(t, err)
	require.Nil(t, details.PurgeRequestedAt)
}

func TestPendingAccountPurges_CountsAndAges(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db, _, email, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	before, _, err := db.PendingAccountPurges(ctx)
	require.NoError(t, err)
	inTx(t, db, func(tx pgx.Tx) {
		_, _, err := db.RequestAccountPurge(ctx, tx, email)
		require.NoError(t, err)
	})
	count, oldest, err := db.PendingAccountPurges(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, count, before+1)
	// The oldest age is over the whole shared test database, where earlier tests leave
	// marks nothing purges, so only its sign is known.
	require.GreaterOrEqual(t, oldest, time.Duration(0))

	details, err := db.GetAccountDetails(ctx, email)
	require.NoError(t, err)
	require.NotNil(t, details.PurgeRequestedAt, "account details show the pending request")
}

// The claim: one holder at a time, the second caller is told it was not claimed.
func TestExecuteWithAccountPurgeLock_SecondCallerNotClaimed(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db, accountID, _, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	ran := false
	claimed, err := db.ExecuteWithAccountPurgeLock(ctx, accountID, func(ctx context.Context) error {
		ran = true
		inner, err := db.ExecuteWithAccountPurgeLock(ctx, accountID, func(context.Context) error {
			t.Error("the lock was granted twice")
			return nil
		})
		require.NoError(t, err)
		require.False(t, inner, "a second claim while the first is held must be refused")
		return nil
	})
	require.NoError(t, err)
	require.True(t, claimed)
	require.True(t, ran)

	// Released with the first call: claimable again.
	claimed, err = db.ExecuteWithAccountPurgeLock(ctx, accountID, func(context.Context) error { return nil })
	require.NoError(t, err)
	require.True(t, claimed)
}

// A purge that keeps failing must not break the backoff arithmetic: PostgreSQL evaluates
// both arguments of LEAST, and 1m * 2^38 does not fit an interval, so once an account has
// failed often enough every further attempt would error instead of backing off.
func TestRecordAccountPurgeFailure_ManyAttemptsDoNotOverflow(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db, accountID, email, _, _ := setupRestoreTestDatabase(t)
	defer db.Close()
	ctx := context.Background()
	inTx(t, db, func(tx pgx.Tx) {
		_, _, err := db.RequestAccountPurge(ctx, tx, email)
		require.NoError(t, err)
	})
	_, err := db.GetWritePool().Exec(ctx, `UPDATE accounts SET purge_attempts = 40 WHERE id = $1`, accountID)
	require.NoError(t, err)

	inTx(t, db, func(tx pgx.Tx) {
		next, err := db.RecordAccountPurgeFailure(ctx, tx, accountID, time.Minute, time.Hour)
		require.NoError(t, err, "attempt 41 must still record a backoff")
		require.WithinDuration(t, time.Now().Add(time.Hour), next, 15*time.Second)
	})
}
