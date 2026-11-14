package db

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/stretchr/testify/require"
)

// credential_changes records every way a login stops working, so that each node can drop
// what it cached of it (GetCredentialChangesSince). The test database is shared with
// packages running at the same time: assertions look only at the accounts a test made.

func credentialChangesAccount(t *testing.T, db *Database, label string) (int64, string) {
	t.Helper()
	email := fmt.Sprintf("credchange-%s-%d@example.com", label, time.Now().UnixNano())
	return createTestAccount(t, db, email, "first-password"), email
}

// dbNow is the database clock, which credential_changes is read by.
func dbNow(t *testing.T, db *Database) time.Time {
	t.Helper()
	var now time.Time
	require.NoError(t, db.GetWritePool().QueryRow(context.Background(), `SELECT clock_timestamp()`).Scan(&now))
	return now
}

// changesSince reports whether the account shows as changed since the given time, and
// whether as taken out of service.
func changesSince(t *testing.T, db *Database, since time.Time, accountID int64) (changed, removed bool) {
	t.Helper()
	ch, err := db.GetCredentialChangesSince(context.Background(), since)
	require.NoError(t, err)
	require.False(t, ch.ReadAt.Before(since), "ReadAt is the database clock at the read")
	return slices.Contains(ch.Accounts, accountID), slices.Contains(ch.Removed, accountID)
}

func TestCredentialChanges_EveryWayALoginStopsWorking(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	accountID, email := credentialChangesAccount(t, db, "a")
	alias := "alias-" + email

	since := dbNow(t, db)
	inTx(t, db, func(tx pgx.Tx) {
		require.NoError(t, db.AddCredential(ctx, tx, AddCredentialRequest{
			AccountID: accountID, NewEmail: alias, NewPassword: "alias-password", NewHashType: "bcrypt",
		}))
	})
	changed, _ := changesSince(t, db, since, accountID)
	require.False(t, changed, "a new credential takes nothing away")

	since = dbNow(t, db)
	inTx(t, db, func(tx pgx.Tx) {
		require.NoError(t, db.UpdateAccount(ctx, tx, UpdateAccountRequest{Email: email, Password: "second-password", HashType: "bcrypt"}))
	})
	changed, removed := changesSince(t, db, since, accountID)
	require.True(t, changed, "a password change is recorded")
	require.False(t, removed, "a password change leaves the account's sessions alone")

	// A transparent rehash replaces the hash of the same password: recorded too, which
	// costs the account one uncached login; telling it from a real change would mean
	// trusting every writer to say which it is.
	since = dbNow(t, db)
	inTx(t, db, func(tx pgx.Tx) {
		hash, err := GenerateBcryptHash("second-password")
		require.NoError(t, err)
		require.NoError(t, db.UpdatePassword(ctx, tx, email, hash))
	})
	changed, _ = changesSince(t, db, since, accountID)
	require.True(t, changed, "any change of the stored hash is recorded")

	since = dbNow(t, db)
	inTx(t, db, func(tx pgx.Tx) {
		require.NoError(t, db.DeleteCredential(ctx, tx, alias))
	})
	changed, removed = changesSince(t, db, since, accountID)
	require.True(t, changed, "a removed credential is recorded")
	require.False(t, removed, "a removed alias leaves the account in service")

	since = dbNow(t, db)
	inTx(t, db, func(tx pgx.Tx) {
		require.NoError(t, db.DeleteAccount(ctx, tx, email))
	})
	changed, removed = changesSince(t, db, since, accountID)
	require.True(t, changed)
	require.True(t, removed, "a deleted account's sessions end")

	deletedSince := since
	since = dbNow(t, db)
	inTx(t, db, func(tx pgx.Tx) {
		require.NoError(t, db.RestoreAccount(ctx, tx, email))
	})
	changed, _ = changesSince(t, db, since, accountID)
	require.False(t, changed, "a restore takes nothing away")
	changed, removed = changesSince(t, db, deletedSince, accountID)
	require.True(t, changed, "the deletion is still a change of logins")
	require.False(t, removed, "a restored account's new sessions are not ended")

	purgedID, purgedEmail := credentialChangesAccount(t, db, "purge")
	since = dbNow(t, db)
	inTx(t, db, func(tx pgx.Tx) {
		_, _, err := db.RequestAccountPurge(ctx, tx, purgedEmail)
		require.NoError(t, err)
	})
	changed, removed = changesSince(t, db, since, purgedID)
	require.True(t, changed)
	require.True(t, removed, "an account marked for purging is out of service: its sessions end")

	// Nothing recorded after the read shows up in it.
	changed, _ = changesSince(t, db, dbNow(t, db), accountID)
	require.False(t, changed)
}

func TestPruneCredentialChanges_DropsOnlyRowsBeforeTheCutoff(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	// Account ids no account has, so the rows are this test's alone.
	base := time.Now().UnixNano()
	oldID, recentID := -base, -base-1
	_, err := db.GetWritePool().Exec(ctx, `
		INSERT INTO credential_changes (account_id, ends_sessions, changed_at)
		VALUES ($1, false, now() - interval '8 days'), ($2, false, now() - interval '6 days')`, oldID, recentID)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.GetWritePool().Exec(context.Background(), `DELETE FROM credential_changes WHERE account_id = ANY($1)`, []int64{oldID, recentID})
	})

	cutoff := dbNow(t, db).Add(-7 * 24 * time.Hour)
	inTx(t, db, func(tx pgx.Tx) {
		pruned, err := db.PruneCredentialChanges(ctx, tx, cutoff)
		require.NoError(t, err)
		require.GreaterOrEqual(t, pruned, int64(1))
	})

	rows, err := db.GetWritePool().Query(ctx, `SELECT account_id FROM credential_changes WHERE account_id = ANY($1)`, []int64{oldID, recentID})
	require.NoError(t, err)
	left, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	require.NoError(t, err)
	require.Equal(t, []int64{recentID}, left)
}

// GetCredentialForToken reads the hash a User API login checks and the epoch its token is
// bound to in one statement, so the epoch is always that of the hash checked.
func TestGetCredentialForToken(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	accountID, email := credentialChangesAccount(t, db, "token")

	id, hash, epoch, err := db.GetCredentialForToken(ctx, email)
	require.NoError(t, err)
	require.Equal(t, accountID, id)
	require.NoError(t, VerifyPassword(hash, "first-password"))
	_, wantEpoch, err := db.GetCredentialEpoch(ctx, email)
	require.NoError(t, err)
	require.True(t, epoch.Equal(wantEpoch))

	inTx(t, db, func(tx pgx.Tx) {
		require.NoError(t, db.DeleteAccount(ctx, tx, email))
	})
	_, _, _, err = db.GetCredentialForToken(ctx, email)
	require.ErrorIs(t, err, consts.ErrUserNotFound, "a deleted account has no login")
}
