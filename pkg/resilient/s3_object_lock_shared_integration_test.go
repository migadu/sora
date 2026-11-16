//go:build integration

package resilient_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// ExecuteWithSharedS3ObjectLocks is how an import claims the bodies it writes: while the
// callback runs it keeps out the cleaner's delete of each body, but not another claim of
// the same bodies, and it holds nothing afterwards. Two pools model two nodes.
func TestSharedS3ObjectLocksKeepOutDeletesNotClaims(t *testing.T) {
	ctx := context.Background()
	nodeA := common.SetupTestDatabase(t)
	nodeB := common.SetupTestDatabase(t)

	const accountID = int64(434343)
	nonce := time.Now().UnixNano()
	hashes := []string{fmt.Sprintf("shared-a-%d", nonce), fmt.Sprintf("shared-b-%d", nonce)}
	// No row references these bodies, so the cleaner confirms every one it can lock.
	objects := make([]db.UserScopedObjectForCleanup, len(hashes))
	for i, hash := range hashes {
		objects[i] = db.UserScopedObjectForCleanup{AccountID: accountID, ContentHash: hash, S3Domain: "example.com", S3Localpart: "shared"}
	}
	confirmed := func() int {
		var n int
		require.NoError(t, nodeB.ExecuteWithLockedS3Orphans(ctx, objects, time.Hour, func(_ context.Context, orphans []db.UserScopedObjectForCleanup) error {
			n = len(orphans)
			return nil
		}))
		return n
	}

	// A body named twice in one claim is locked once.
	require.NoError(t, nodeA.ExecuteWithSharedS3ObjectLocks(ctx, accountID, []string{hashes[0], hashes[1], hashes[0]}, func(guarded context.Context) error {
		require.NoError(t, guarded.Err(), "the guarded context must be live while the locks are held")

		claimed := make(chan error, 1)
		go func() {
			claimed <- nodeB.ExecuteWithSharedS3ObjectLocks(ctx, accountID, hashes, func(context.Context) error { return nil })
		}()
		select {
		case err := <-claimed:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("a second claim of the bodies waited for the first")
		}

		require.Zero(t, confirmed(), "the cleaner confirmed a claimed body as an orphan")
		return nil
	}))

	require.Equal(t, len(hashes), confirmed(), "the claim must release every lock when the callback returns")
	for _, hash := range hashes {
		require.Equal(t, 0, advisoryLockEntries(t, nodeB, db.GetS3ObjectLockID(accountID, hash)), "no lock-table entry may survive the callback")
	}
}
