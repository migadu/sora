//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// TestRename_SharedBoundaryDescendants covers issue #1229. RENAME carries the
// mailbox's children along, and a child can cross the shared namespace boundary
// although the mailbox does not: here a personal "Shared" from before sharing was
// enabled, with a shared child. Renaming it out of the namespace would take the
// shared child, and its grants, out too. The RENAME is refused with NO [CANNOT]
// before the new name's parent is created.
func TestRename_SharedBoundaryDescendants(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	server, owner := common.SetupIMAPServerWithOptions(t, sharedMailboxSettings(true, false))
	defer server.Close()

	adminCtx := adminSharedContext("Shared/")
	ownerID, err := server.ResilientDB.GetAccountIDByEmailWithRetry(adminCtx, owner.Email)
	require.NoError(t, err)
	ts := common.GetTimestamp()
	child := fmt.Sprintf("Shared/Team-%d", ts)
	require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(context.Background(), ownerID, "Shared"))
	require.NoError(t, server.ResilientDB.CreateMailboxForUserWithRetry(adminCtx, ownerID, child))

	c := loginClient(t, server, owner.Email, owner.Password)

	newParent := fmt.Sprintf("Archive-%d", ts)
	requireResponseCode(t, c.Rename("Shared", newParent+"/Old", nil).Wait(), imap.ResponseCodeCannot,
		"RENAME of a personal mailbox with a shared child out of the shared namespace")
	names := mailboxNames(t, c)
	require.Contains(t, names, "Shared")
	require.Contains(t, names, child)
	require.NotContains(t, names, newParent+"/Old/"+fmt.Sprintf("Team-%d", ts))
	require.NotContains(t, names, newParent, "a refused RENAME left the parent it created behind")
}
