package db

import (
	"context"
	"fmt"
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

// diagnosticChangesSince reports whether the account shows as changed since the given time, and
// whether as taken out of service.
// Trigger diagnostics below use changed_at to identify the mutation under test;
// delivery ordering is exercised separately by the snapshot-cursor tests.
func diagnosticChangesSince(t *testing.T, d *Database, since time.Time, accountID int64) (changed, removed bool) {
	t.Helper()
	err := d.GetWritePool().QueryRow(context.Background(), `SELECT
 EXISTS(SELECT 1 FROM credential_changes WHERE account_id=$1 AND changed_at >=$2),
 EXISTS(SELECT 1 FROM credential_changes c WHERE c.account_id=$1 AND c.changed_at >=$2 AND c.ends_sessions AND NOT EXISTS(SELECT 1 FROM accounts a WHERE a.id=c.account_id AND a.deleted_at IS NULL))`, accountID, since).Scan(&changed, &removed)
	require.NoError(t, err)
	return changed, removed
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
	changed, _ := diagnosticChangesSince(t, db, since, accountID)
	require.False(t, changed, "a new credential takes nothing away")

	since = dbNow(t, db)
	inTx(t, db, func(tx pgx.Tx) {
		require.NoError(t, db.UpdateAccount(ctx, tx, UpdateAccountRequest{Email: email, Password: "second-password", HashType: "bcrypt"}))
	})
	changed, removed := diagnosticChangesSince(t, db, since, accountID)
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
	changed, _ = diagnosticChangesSince(t, db, since, accountID)
	require.True(t, changed, "any change of the stored hash is recorded")

	since = dbNow(t, db)
	inTx(t, db, func(tx pgx.Tx) {
		require.NoError(t, db.DeleteCredential(ctx, tx, alias))
	})
	changed, removed = diagnosticChangesSince(t, db, since, accountID)
	require.True(t, changed, "a removed credential is recorded")
	require.False(t, removed, "a removed alias leaves the account in service")

	since = dbNow(t, db)
	inTx(t, db, func(tx pgx.Tx) {
		require.NoError(t, db.DeleteAccount(ctx, tx, email))
	})
	changed, removed = diagnosticChangesSince(t, db, since, accountID)
	require.True(t, changed)
	require.True(t, removed, "a deleted account's sessions end")

	deletedSince := since
	since = dbNow(t, db)
	inTx(t, db, func(tx pgx.Tx) {
		require.NoError(t, db.RestoreAccount(ctx, tx, email))
	})
	changed, _ = diagnosticChangesSince(t, db, since, accountID)
	require.False(t, changed, "a restore takes nothing away")
	changed, removed = diagnosticChangesSince(t, db, deletedSince, accountID)
	require.True(t, changed, "the deletion is still a change of logins")
	require.False(t, removed, "a restored account's new sessions are not ended")

	purgedID, purgedEmail := credentialChangesAccount(t, db, "purge")
	since = dbNow(t, db)
	inTx(t, db, func(tx pgx.Tx) {
		_, _, err := db.RequestAccountPurge(ctx, tx, purgedEmail)
		require.NoError(t, err)
	})
	changed, removed = diagnosticChangesSince(t, db, since, purgedID)
	require.True(t, changed)
	require.True(t, removed, "an account marked for purging is out of service: its sessions end")

	hardID, _ := credentialChangesAccount(t, db, "direct-hard-delete")
	since = dbNow(t, db)
	inTx(t, db, func(tx pgx.Tx) {
		_, err := tx.Exec(ctx, "DELETE FROM credentials WHERE account_id=$1", hardID)
		require.NoError(t, err)
		_, err = tx.Exec(ctx, "DELETE FROM accounts WHERE id=$1", hardID)
		require.NoError(t, err)
	})
	changed, removed = diagnosticChangesSince(t, db, since, hardID)
	require.True(t, changed, "direct hard deletion records a revocation")
	require.True(t, removed, "direct hard deletion ends local sessions too")

	// Nothing recorded after the read shows up in it.
	changed, _ = diagnosticChangesSince(t, db, dbNow(t, db), accountID)
	require.False(t, changed)
}

// Deferred triggers normally stamp the diagnostic changed_at near commit. This
// timing is not the delivery guarantee: SET CONSTRAINTS may fire them earlier,
// which the separate transaction-cursor regression exercises.
func TestCredentialChanges_StampedAtCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	db := setupTestDatabase(t)
	defer db.Close()
	ctx := context.Background()

	accountID, email := credentialChangesAccount(t, db, "commit")
	removedID, removedEmail := credentialChangesAccount(t, db, "commit-removed")

	var afterChanges time.Time
	inTx(t, db, func(tx pgx.Tx) {
		require.NoError(t, db.UpdateAccount(ctx, tx, UpdateAccountRequest{Email: email, Password: "second-password", HashType: "bcrypt"}))
		require.NoError(t, db.DeleteAccount(ctx, tx, removedEmail))
		// The transaction goes on after the changes.
		require.NoError(t, tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&afterChanges))
	})

	changed, _ := diagnosticChangesSince(t, db, afterChanges, accountID)
	require.True(t, changed, "the password change was stamped before the commit, not at it")
	changed, removed := diagnosticChangesSince(t, db, afterChanges, removedID)
	require.True(t, changed, "the deletion was stamped before the commit, not at it")
	require.True(t, removed)

	// A change rolled back is not recorded at all.
	since := dbNow(t, db)
	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.UpdateAccount(ctx, tx, UpdateAccountRequest{Email: email, Password: "third-password", HashType: "bcrypt"}))
	require.NoError(t, tx.Rollback(ctx))
	changed, _ = diagnosticChangesSince(t, db, since, accountID)
	require.False(t, changed, "a rolled-back change is recorded")
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
	oldID, recentID, unseenID := -base, -base-1, -base-2
	_, err := db.GetWritePool().Exec(ctx, `
		INSERT INTO credential_changes (account_id, ends_sessions, changed_at, first_observed_at)
 VALUES ($1,false,now()-interval '8 days',now()-interval '8 days'),($2,false,now()-interval '8 days',now()-interval '6 days'),($3,false,now()-interval '8 days',NULL)`, oldID, recentID, unseenID)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = db.GetWritePool().Exec(context.Background(), `DELETE FROM credential_changes WHERE account_id = ANY($1)`, []int64{oldID, recentID, unseenID})
	})

	cutoff := dbNow(t, db).Add(-7 * 24 * time.Hour)
	inTx(t, db, func(tx pgx.Tx) {
		// No assertion on the count: every node's watcher, and any test running one
		// against this database meanwhile, prunes the same rows, so the old one may
		// already be gone.
		_, err := db.PruneCredentialChanges(ctx, tx, cutoff)
		require.NoError(t, err)
	})

	rows, err := db.GetWritePool().Query(ctx, `SELECT account_id FROM credential_changes WHERE account_id = ANY($1)`, []int64{oldID, recentID, unseenID})
	require.NoError(t, err)
	left, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	require.NoError(t, err)
	require.ElementsMatch(t, []int64{recentID, unseenID}, left)
	var observed time.Time
	require.NoError(t, db.GetWritePool().QueryRow(ctx, "SELECT first_observed_at FROM credential_changes WHERE account_id=$1", unseenID).Scan(&observed))
	require.True(t, observed.After(cutoff), "an old writer timestamp must receive a fresh observation interval")
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
