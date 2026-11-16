//go:build integration

package resilient_test

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetOrCreateMailboxByNameWithRetry_CreatedConcurrently is issue #1396: a mailbox
// (or a missing parent of it) that another transaction creates while the
// get-or-create behind Sieve fileinto :create and the importer creates it too must
// be read back and used, not fail the call with "current transaction is aborted"
// (SQLSTATE 25P02).
func TestGetOrCreateMailboxByNameWithRetry_CreatedConcurrently(t *testing.T) {
	rdb := common.SetupTestDatabase(t)
	dbLayer := rdb.GetOperationalDatabase()

	for _, tc := range []struct {
		name   string
		target string // asked for while the other transaction creates "Alpha"
	}{
		{name: "target", target: "Alpha"},
		{name: "parent", target: "Alpha/Beta"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			account := common.CreateTestAccount(t, rdb)
			accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
			require.NoError(t, err)

			// The other creator of "Alpha", done but not committed.
			txOther, err := dbLayer.GetWritePool().Begin(ctx)
			require.NoError(t, err)
			defer txOther.Rollback(context.Background())
			var otherPID int
			require.NoError(t, txOther.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&otherPID))
			require.NoError(t, dbLayer.CreateMailbox(ctx, txOther, accountID, "Alpha", nil))

			type result struct {
				mb  *db.DBMailbox
				err error
			}
			done := make(chan result, 1)
			go func() {
				mb, err := rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, tc.target)
				done <- result{mb, err}
			}()

			// Its lookup of "Alpha" sees nothing, so it inserts "Alpha" too and waits
			// on the unique index for the other transaction.
			require.Eventually(t, func() bool {
				var waiting bool
				err := dbLayer.GetWritePool().QueryRow(ctx,
					`SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))`, otherPID).Scan(&waiting)
				return err == nil && waiting
			}, 10*time.Second, 5*time.Millisecond, "the get-or-create did not wait for the other creator of Alpha")

			require.NoError(t, txOther.Commit(ctx))
			var res result
			select {
			case res = <-done:
			case <-time.After(30 * time.Second):
				t.Fatal("GetOrCreateMailboxByNameWithRetry did not return after the other creator committed")
			}
			require.NoError(t, res.err, "a mailbox created concurrently must be read back and used")
			assert.Equal(t, tc.target, res.mb.Name)

			alpha, err := dbLayer.GetMailboxByName(ctx, accountID, "Alpha")
			require.NoError(t, err)
			got, err := dbLayer.GetMailboxByName(ctx, accountID, tc.target)
			require.NoError(t, err)
			assert.Equal(t, res.mb.ID, got.ID)
			if tc.target == "Alpha" {
				assert.Equal(t, alpha.ID, res.mb.ID, "the other transaction's Alpha must be returned")
			} else {
				assert.True(t, alpha.HasChildren, "Alpha/Beta must be linked below the other transaction's Alpha")
				assert.Equal(t, alpha.Path, got.Path[:len(alpha.Path)])
			}
			subscribed, err := dbLayer.GetSubscribedMailboxNames(ctx, accountID)
			require.NoError(t, err)
			assert.Contains(t, subscribed, tc.target)
		})
	}
}
