package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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

			pidCh := make(chan uint32, 1)
			secondErr := make(chan error, 1)
			go func() {
				tx, err := database.GetWritePool().Begin(ctx)
				if err != nil {
					secondErr <- err
					return
				}
				defer tx.Rollback(context.Background())
				var pid uint32
				if err := tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
					secondErr <- err
					return
				}
				pidCh <- pid
				if err := tc.second.run(ctx, tx, accountID, c); err != nil {
					secondErr <- err
					return
				}
				secondErr <- tx.Commit(ctx)
			}()

			var pid uint32
			select {
			case pid = <-pidCh:
			case err := <-secondErr:
				t.Fatalf("second change failed to start: %v", err)
			}
			for {
				var waitType *string
				require.NoError(t, database.GetWritePool().QueryRow(ctx,
					"SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1", pid).Scan(&waitType))
				if waitType != nil && *waitType == "Lock" {
					break
				}
				select {
				case err := <-secondErr:
					t.Fatalf("second change finished while the first was open: %v", err)
				case <-ctx.Done():
					t.Fatal("timed out waiting for the second change to block")
				case <-time.After(10 * time.Millisecond):
				}
			}

			require.NoError(t, first.Commit(ctx), "first change")
			require.NoError(t, <-secondErr, "second change")

			rows, err := database.GetWritePool().Query(ctx,
				"SELECT address FROM credentials WHERE account_id = $1 AND primary_identity", accountID)
			require.NoError(t, err)
			primary, err := pgx.CollectRows(rows, pgx.RowTo[string])
			require.NoError(t, err)
			require.Equal(t, []string{c}, primary)
		})
	}
}
