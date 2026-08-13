package uploader

import (
	"context"
	"testing"

	"github.com/migadu/sora/db"
)

// max_staging_size guards THIS node's staging directory, which holds message bodies on
// its own local disk. The guard is consulted by every delivery path - IMAP APPEND
// (server/imap/append.go:304), LMTP (server/lmtp/session.go:696) and the Admin API
// (server/delivery/delivery.go:169) - and a message over the limit is REJECTED, not
// queued.
//
// So the number it is measured against has to be this instance's own staged bytes.
// db.GetUploaderStats sums pending_uploads across the whole cluster with no instance
// filter, and rebasing the local counter from that total makes one node's backlog reject
// mail on every other node, however empty their disks are.
func TestStagingGuardCountsOnlyThisInstance(t *testing.T) {
	const (
		maxStaging  = 100 << 20 // 100 MiB
		localBytes  = 1 << 20   // this node has staged 1 MiB
		clusterWide = 4 << 30   // four peers are sitting on 4 GiB between them
	)

	rdb := &mockDB{}
	rdb.GetUploaderStatsWithRetryFunc = func(ctx context.Context, maxAttempts int) (*db.UploaderStats, error) {
		// Cluster-wide totals: what every node's pending_uploads add up to.
		return &db.UploaderStats{TotalPending: 100000, TotalPendingSize: clusterWide, FailedUploads: 0}, nil
	}
	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		// This instance's own share of it.
		return UploadBacklog{Count: 256, Bytes: localBytes}, nil
	}

	worker := &UploadWorker{
		rdb:            rdb,
		instanceID:     "mail-07",
		maxAttempts:    5,
		maxStagingSize: maxStaging,
	}

	if err := worker.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads: %v", err)
	}

	if worker.IsStagingLimitExceeded(4096) {
		t.Errorf("this node refuses a 4 KiB delivery with only %d bytes staged locally against a "+
			"%d byte limit: the guard was rebased from the cluster-wide total (%d bytes), so one "+
			"node's backlog rejects mail on every node",
			localBytes, int64(maxStaging), int64(clusterWide))
	}

	// The guard must still fire on this node's own overrun.
	if !worker.IsStagingLimitExceeded(maxStaging) {
		t.Error("the staging guard no longer fires when this instance's own staged bytes exceed the limit")
	}
}
