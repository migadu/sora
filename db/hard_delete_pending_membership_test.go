package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestListSoftDeletedPendingMembershipHandlesNullAndDuplicates(t *testing.T) {
	database := setupTestDatabase(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	marker := finalizeTestMarker(t, database)
	grace := time.Since(marker.Add(time.Minute))
	makeAccount := func(tag string) int64 {
		id, _ := setupSoftDeletedAccountForDependentsTest(t, database, marker, tag)
		_, err := database.GetWritePool().Exec(ctx, "DELETE FROM mailboxes WHERE account_id=$1", id)
		require.NoError(t, err)
		return id
	}
	eligible := makeAccount("duplicatepending")
	liveOnly := makeAccount("livepending")
	finished := makeAccount("finishedpending")
	restored := makeAccount("restoredpending")
	nullHash := fmt.Sprintf("membership-null-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, err := database.GetWritePool().Exec(ctx, "DELETE FROM pending_uploads WHERE content_hash=$1", nullHash)
		require.NoError(t, err)
	})
	_, err := database.GetWritePool().Exec(ctx, `
		INSERT INTO pending_uploads(account_id,content_hash,size,instance_id,lease_until)
		VALUES ($1,'member-a',1,'membership',NULL),
		       ($1,'member-b',1,'membership',now()-interval '1 hour'),
		       ($1,'member-c',1,'membership',now()+interval '1 hour'),
		       ($2,'live-only',1,'membership',now()+interval '1 hour'),
		       ($3,'restored',1,'membership',NULL),
		       (NULL,$4,1,'membership',NULL)
	`, eligible, liveOnly, restored, nullHash)
	require.NoError(t, err)
	_, err = database.GetWritePool().Exec(ctx, "UPDATE accounts SET deleted_at=NULL WHERE id=$1", restored)
	require.NoError(t, err)
	ids, err := database.ListSoftDeletedAccountsForHardDelete(ctx, grace, 100000)
	require.NoError(t, err)
	count := 0
	for _, id := range ids {
		if id == eligible {
			count++
		}
	}
	require.Equal(t, 1, count, "duplicate pending rows select an account once, even with a NULL-account row in the set")
	require.NotContains(t, ids, liveOnly, "a live lease alone is not actionable")
	require.NotContains(t, ids, finished, "NULL membership must not select an account with no remaining work")
	require.NotContains(t, ids, restored, "dependency membership never overrides the soft-deleted predicate")
}
