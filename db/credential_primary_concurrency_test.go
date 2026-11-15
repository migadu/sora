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

// Two primary-identity changes of one account, the second starting while the first is
// uncommitted (#1503). The second read which credential was primary before the first
// committed, so it cleared nothing and then set its own credential primary next to the
// first one's, failing on idx_credentials_account_id_one_primary (23505). In either
// serial order both succeed, and the later one leaves its credential primary.
func TestPrimaryIdentity_ConcurrentChangesOfOneAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	database := setupTestDatabase(t)

	// changeFunc makes address the primary identity of the account, either by promoting
	// an existing credential (UpdateAccount) or by adding a new one (AddCredential).
	type changeFunc struct {
		name     string
		existing bool // address must already be a credential of the account
		run      func(ctx context.Context, tx pgx.Tx, accountID int64, address string) error
	}
	update := changeFunc{"UpdateAccount", true, func(ctx context.Context, tx pgx.Tx, _ int64, address string) error {
		return database.UpdateAccount(ctx, tx, UpdateAccountRequest{Email: address, MakePrimary: true})
	}}
	updatePassword := changeFunc{"UpdateAccount with password", true, func(ctx context.Context, tx pgx.Tx, _ int64, address string) error {
		return database.UpdateAccount(ctx, tx, UpdateAccountRequest{Email: address, Password: "pw", HashType: "ssha512", MakePrimary: true})
	}}
	add := changeFunc{"AddCredential", false, func(ctx context.Context, tx pgx.Tx, accountID int64, address string) error {
		return database.AddCredential(ctx, tx, AddCredentialRequest{
			AccountID: accountID, NewEmail: address, NewPassword: "pw", NewHashType: "ssha512", IsPrimary: true,
		})
	}}

	for _, tc := range []struct{ first, second changeFunc }{
		{update, update},
		{updatePassword, update},
		{add, add},
		{update, add},
		{add, update},
	} {
		t.Run(tc.first.name+" then "+tc.second.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			domain := fmt.Sprintf("primary-race-%d.example.com", time.Now().UnixNano())
			a, b, c := "a@"+domain, "b@"+domain, "c@"+domain
			accountID, _ := setupAccountWithInbox(t, database, ctx, a)
			for _, step := range []struct {
				change  changeFunc
				address string
			}{{tc.first, b}, {tc.second, c}} {
				if step.change.existing {
					require.NoError(t, addCredentialTx(t, database, ctx, AddCredentialRequest{
						AccountID: accountID, NewEmail: step.address, NewPassword: "pw", NewHashType: "ssha512",
					}))
				}
			}

			// The first change has run and is not committed yet.
			first, err := database.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer first.Rollback(context.Background())
			require.NoError(t, tc.first.run(ctx, first, accountID, b), "first change")

			secondErr := startBlockedChange(t, ctx, database, func(ctx context.Context, tx pgx.Tx) error {
				return tc.second.run(ctx, tx, accountID, c)
			})

			require.NoError(t, first.Commit(ctx), "first change")
			require.NoError(t, <-secondErr, "second change")

			require.Equal(t, []string{c}, primaryAddresses(t, ctx, database, accountID))
		})
	}
}

// A primary-identity change whose credential is deleted while it waits must fail and roll
// back its clearing of the current primary instead of committing the account without a
// primary identity. It waits either for another primary change's lock (the clearing UPDATE
// then sees and clears that change's committed primary) or for the delete's row lock on
// the credential (after it cleared the old primary). In both cases the UPDATE that sets the
// credential primary finds no row.
func TestUpdateAccount_MakePrimaryOfConcurrentlyDeletedCredential(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	database := setupTestDatabase(t)

	for _, tc := range []struct {
		name string
		// block opens what c's promotion waits for and returns the addresses that must
		// be primary afterwards.
		block func(t *testing.T, ctx context.Context, a, b, c string) (release func(), want []string)
	}{
		{"waiting for another primary change", func(t *testing.T, ctx context.Context, a, b, c string) (func(), []string) {
			first, err := database.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			t.Cleanup(func() { first.Rollback(context.Background()) })
			require.NoError(t, database.UpdateAccount(ctx, first, UpdateAccountRequest{Email: b, MakePrimary: true}))
			return func() {
				deleteCredentialTx(t, ctx, database, c)
				require.NoError(t, first.Commit(ctx))
			}, []string{b}
		}},
		{"waiting for the delete's row lock", func(t *testing.T, ctx context.Context, a, b, c string) (func(), []string) {
			del, err := database.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			t.Cleanup(func() { del.Rollback(context.Background()) })
			require.NoError(t, database.DeleteCredential(ctx, del, c))
			return func() { require.NoError(t, del.Commit(ctx)) }, []string{a}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			domain := fmt.Sprintf("primary-delete-race-%d.example.com", time.Now().UnixNano())
			a, b, c := "a@"+domain, "b@"+domain, "c@"+domain
			accountID, _ := setupAccountWithInbox(t, database, ctx, a)
			for _, address := range []string{b, c} {
				require.NoError(t, addCredentialTx(t, database, ctx, AddCredentialRequest{
					AccountID: accountID, NewEmail: address, NewPassword: "pw", NewHashType: "ssha512",
				}))
			}

			release, want := tc.block(t, ctx, a, b, c)
			promote := startBlockedChange(t, ctx, database, func(ctx context.Context, tx pgx.Tx) error {
				return database.UpdateAccount(ctx, tx, UpdateAccountRequest{Email: c, MakePrimary: true})
			})
			release()

			err := <-promote
			require.Equal(t, want, primaryAddresses(t, ctx, database, accountID))
			require.ErrorIs(t, err, consts.ErrUserNotFound)
		})
	}
}

// startBlockedChange runs change in its own transaction in a goroutine and commits it if
// change succeeds. It returns once the transaction waits for a lock; the channel yields
// change's or the commit's error.
func startBlockedChange(t *testing.T, ctx context.Context, database *Database, change func(ctx context.Context, tx pgx.Tx) error) <-chan error {
	t.Helper()
	pidCh := make(chan uint32, 1)
	done := make(chan error, 1)
	go func() {
		tx, err := database.GetWritePool().Begin(ctx)
		if err != nil {
			done <- err
			return
		}
		defer tx.Rollback(context.Background())
		var pid uint32
		if err := tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
			done <- err
			return
		}
		pidCh <- pid
		if err := change(ctx, tx); err != nil {
			done <- err
			return
		}
		done <- tx.Commit(ctx)
	}()

	var pid uint32
	select {
	case pid = <-pidCh:
	case err := <-done:
		t.Fatalf("change failed to start: %v", err)
	}
	for {
		var waitType *string
		require.NoError(t, database.GetWritePool().QueryRow(ctx,
			"SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1", pid).Scan(&waitType))
		if waitType != nil && *waitType == "Lock" {
			return done
		}
		select {
		case err := <-done:
			t.Fatalf("change finished without waiting for a lock: %v", err)
		case <-ctx.Done():
			t.Fatal("timed out waiting for the change to block")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func deleteCredentialTx(t *testing.T, ctx context.Context, database *Database, address string) {
	t.Helper()
	tx, err := database.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	require.NoError(t, database.DeleteCredential(ctx, tx, address))
	require.NoError(t, tx.Commit(ctx))
}

func primaryAddresses(t *testing.T, ctx context.Context, database *Database, accountID int64) []string {
	t.Helper()
	rows, err := database.GetWritePool().Query(ctx,
		"SELECT address FROM credentials WHERE account_id = $1 AND primary_identity", accountID)
	require.NoError(t, err)
	primary, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	return primary
}
