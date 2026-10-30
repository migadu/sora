package uploader

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/db"
)

// The stuck-upload report lists failed rows of every instance (GetFailedUploads has no
// instance filter), so it logs hashes this node never wrote. Abbreviating one shorter
// than the abbreviation panicked the monitor goroutine, and that took the process down.
func TestStuckUploadReportToleratesShortHash(t *testing.T) {
	rdb := &mockDB{}
	rdb.GetUploaderStatsWithRetryFunc = func(ctx context.Context, maxAttempts int) (*db.UploaderStats, error) {
		return &db.UploaderStats{FailedUploads: 1}, nil
	}
	rdb.GetFailedUploadsWithRetryFunc = func(ctx context.Context, maxAttempts int, limit int) ([]db.PendingUpload, error) {
		return []db.PendingUpload{{ID: 1, AccountID: 7, ContentHash: "hash1", Attempts: 5, CreatedAt: time.Now()}}, nil
	}

	worker := &UploadWorker{rdb: rdb, instanceID: "mail-07", maxAttempts: 5}
	if err := worker.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads: %v", err)
	}
}
