package cleaner

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/require"
)

type fakeDisabler struct {
	accountID   int64
	deleteErr   error
	lookupOnPri bool
}

func (f *fakeDisabler) GetAccountIDByEmailWithRetry(ctx context.Context, _ string) (int64, error) {
	f.lookupOnPri, _ = ctx.Value(consts.UseMasterDBKey).(bool)
	return f.accountID, nil
}

func (f *fakeDisabler) DeleteAccountWithRetry(_ context.Context, _ string) error {
	return f.deleteErr
}

// TestDisableAccount_ReadsPrimary ensures DisableAccount pins its address lookup to the
// primary so a lagging read replica cannot hide a just-created account or return the id
// of an earlier account that held the same address, and accepts an account that is
// already soft-deleted.
func TestDisableAccount_ReadsPrimary(t *testing.T) {
	d := &fakeDisabler{accountID: 42, deleteErr: db.ErrAccountAlreadyDeleted}
	id, err := DisableAccount(context.Background(), d, "user@example.com")
	require.NoError(t, err)
	require.Equal(t, int64(42), id)
	require.True(t, d.lookupOnPri, "DisableAccount must resolve the address on the primary")
}

type fakePurgeObjectDB struct {
	batches [][]db.UserScopedObjectForCleanup
	cursors []db.UserScopedObjectForCleanup
	locked  map[string]bool
	deleted int64
}

func (f *fakePurgeObjectDB) HardDeleteAccountWithRetry(context.Context, int64) error { return nil }
func (f *fakePurgeObjectDB) DeleteFTSRowsForAccountWithRetry(context.Context, int64, int) (int64, error) {
	return 0, nil
}
func (f *fakePurgeObjectDB) FinalizeAccountDeletionsWithRetry(context.Context, []int64) (int64, error) {
	return 1, nil
}
func (f *fakePurgeObjectDB) GetAccountDeletionStateWithRetry(context.Context, int64) (bool, bool, error) {
	return false, false, nil
}

func (f *fakePurgeObjectDB) GetPurgeableObjectsForAccountWithRetry(_ context.Context, _ int64, after db.UserScopedObjectForCleanup, _ int) ([]db.UserScopedObjectForCleanup, error) {
	f.cursors = append(f.cursors, after)
	if len(f.batches) == 0 {
		return nil, nil
	}
	b := f.batches[0]
	f.batches = f.batches[1:]
	return b, nil
}

func (f *fakePurgeObjectDB) ExecuteWithLockedS3Orphans(ctx context.Context, objects []db.UserScopedObjectForCleanup, _ time.Duration, fn func(ctx context.Context, orphans []db.UserScopedObjectForCleanup) error) error {
	var orphans []db.UserScopedObjectForCleanup
	for _, o := range objects {
		if !f.locked[o.ContentHash] {
			orphans = append(orphans, o)
		}
	}
	return fn(ctx, orphans)
}

func (f *fakePurgeObjectDB) DeleteExpungedMessagesByS3KeyPartsBatchWithRetry(_ context.Context, objects []db.UserScopedObjectForCleanup) (int64, error) {
	n := int64(len(objects))
	f.deleted += n
	return n, nil
}

type okBulkDeleter struct{}

func (okBulkDeleter) DeleteBulkWithRetry(context.Context, []string) map[string]error { return nil }

// TestPurgeAccountObjects_AdvancesCursorPastSkippedObjects verifies that when a full batch
// of purgeable objects contains a skipped object (e.g. an upload in flight holding its
// lock), purgeAccountObjects advances the keyset cursor past the batch instead of
// re-fetching the skipped object on every subsequent batch of the same pass.
func TestPurgeAccountObjects_AdvancesCursorPastSkippedObjects(t *testing.T) {
	firstBatch := make([]db.UserScopedObjectForCleanup, purgeObjectBatch)
	for i := range firstBatch {
		firstBatch[i] = db.UserScopedObjectForCleanup{
			AccountID:   7,
			S3Domain:    "example.com",
			S3Localpart: "u",
			ContentHash: fmt.Sprintf("h-%04d", i),
		}
	}
	secondBatch := []db.UserScopedObjectForCleanup{
		{AccountID: 7, S3Domain: "example.com", S3Localpart: "u", ContentHash: "h-1000"},
		{AccountID: 7, S3Domain: "example.com", S3Localpart: "u", ContentHash: "h-1001"},
	}

	rdb := &fakePurgeObjectDB{
		batches: [][]db.UserScopedObjectForCleanup{firstBatch, secondBatch},
		locked:  map[string]bool{"h-0000": true}, // first object in batch 1 is locked by an upload
	}

	var stats PurgeStats
	require.NoError(t, purgeAccountObjects(context.Background(), rdb, okBulkDeleter{}, 7, &stats))

	require.Len(t, rdb.cursors, 2, "must stop after the short second batch without an extra empty query")
	require.Equal(t, db.UserScopedObjectForCleanup{}, rdb.cursors[0], "first round starts from zero cursor")
	require.Equal(t, firstBatch[len(firstBatch)-1], rdb.cursors[1], "second round starts after the last object of the first batch")
	require.Equal(t, purgeObjectBatch-1+len(secondBatch), stats.S3Objects)
	require.Equal(t, int64(purgeObjectBatch-1+len(secondBatch)), stats.Messages)
}
