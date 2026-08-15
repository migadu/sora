package uploader

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The stall warning fires at most once an hour, which makes it a poor alerting surface.
// sora_queue_processing_lag_seconds is the one an operator can write a rule against, and
// this backlog is a mail-loss path: the bodies exist only on this instance's disk, and
// db.CleanupFailedUploads deletes their messages once the instance stops looking alive.
func TestBacklogAgeIsPublishedAsAMetric(t *testing.T) {
	const oldestAge = 3 * time.Hour

	rdb := &mockDB{}
	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		return UploadBacklog{Count: 12, Bytes: 4096, Oldest: time.Now().Add(-oldestAge)}, nil
	}

	worker := &UploadWorker{rdb: rdb, instanceID: "mail-07", maxAttempts: 5}
	if err := worker.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads: %v", err)
	}

	got := testutil.ToFloat64(metrics.QueueProcessingLag.WithLabelValues("s3_upload"))
	if got < oldestAge.Seconds()-60 || got > oldestAge.Seconds()+60 {
		t.Errorf("sora_queue_processing_lag_seconds{queue_type=\"s3_upload\"} = %v, want ~%v: "+
			"without it a stalled upload queue is only visible as an hourly log line", got, oldestAge.Seconds())
	}
}

// TestBacklogAgeResetsWhenTheQueueDrains keeps the gauge from latching. A value left at
// its last stalled reading would alert forever after the queue recovered, which is the
// fastest way to get an alert switched off permanently.
func TestBacklogAgeResetsWhenTheQueueDrains(t *testing.T) {
	rdb := &mockDB{}
	backlog := UploadBacklog{Count: 5, Bytes: 2048, Oldest: time.Now().Add(-2 * time.Hour)}
	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		return backlog, nil
	}

	worker := &UploadWorker{rdb: rdb, instanceID: "mail-07", maxAttempts: 5}
	if err := worker.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads: %v", err)
	}
	if got := testutil.ToFloat64(metrics.QueueProcessingLag.WithLabelValues("s3_upload")); got == 0 {
		t.Fatal("gauge never reported the stalled backlog, so the drain assertion below proves nothing")
	}

	backlog = UploadBacklog{} // drained
	if err := worker.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads: %v", err)
	}

	if got := testutil.ToFloat64(metrics.QueueProcessingLag.WithLabelValues("s3_upload")); got != 0 {
		t.Errorf("sora_queue_processing_lag_seconds = %v after the queue drained, want 0: "+
			"a latched gauge keeps a resolved alert firing", got)
	}
}
