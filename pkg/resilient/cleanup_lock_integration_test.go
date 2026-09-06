//go:build integration

package resilient_test

import (
	"context"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// The cleanup lock must exclude a second node for the whole cycle. It once was a
// transaction-scoped advisory lock taken inside a wrapper that committed at once, so it
// was released before the cycle ran and every node ran every cycle. Two independent
// pools model two nodes.
func TestCleanupLockExcludesSecondNodeForTheCycle(t *testing.T) {
	ctx := context.Background()
	nodeA := common.SetupTestDatabase(t)
	nodeB := common.SetupTestDatabase(t)

	gotA, err := nodeA.AcquireCleanupLockWithRetry(ctx)
	require.NoError(t, err)
	require.True(t, gotA, "node A must get the lock")

	gotB, err := nodeB.AcquireCleanupLockWithRetry(ctx)
	require.NoError(t, err)
	require.False(t, gotB, "node B must be excluded while A's cycle runs")

	// Re-entry within the same process is refused too (a cycle is already running).
	again, err := nodeA.AcquireCleanupLockWithRetry(ctx)
	require.Error(t, err)
	require.False(t, again)

	require.NoError(t, nodeA.ReleaseCleanupLockWithRetry(ctx))

	gotB, err = nodeB.AcquireCleanupLockWithRetry(ctx)
	require.NoError(t, err)
	require.True(t, gotB, "after A releases, B gets the lock")
	require.NoError(t, nodeB.ReleaseCleanupLockWithRetry(ctx))

	// Releasing without holding is harmless.
	require.NoError(t, nodeA.ReleaseCleanupLockWithRetry(ctx))
}
