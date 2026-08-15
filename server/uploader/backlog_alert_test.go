package uploader

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/db"
)

// syncBuffer serialises writes from the slog handler, so the capture is safe under
// -race even if a log line is emitted from another goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLogs redirects the default slog logger (which logger.Get() falls back to when
// the process never called logger.Initialize) for the duration of the test.
func captureLogs(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return buf
}

// stalledBacklogWorker is a worker whose instance owns a backlog of the given age with
// no upload anywhere near max_attempts, i.e. the state a prolonged transient S3 failure
// produces: processSingleUpload deliberately does not count transient errors, so
// attempts stay at 0 no matter how long the outage lasts.
func stalledBacklogWorker(t *testing.T, oldestAge time.Duration, count int64) (*UploadWorker, *mockDB) {
	t.Helper()

	rdb := &mockDB{}
	rdb.GetUploaderStatsWithRetryFunc = func(ctx context.Context, maxAttempts int) (*db.UploaderStats, error) {
		// No upload has exhausted its attempts, so the failed-upload alert stays silent.
		return &db.UploaderStats{TotalPending: count, TotalPendingSize: count * 4096, FailedUploads: 0}, nil
	}
	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		if count == 0 {
			return UploadBacklog{}, nil
		}
		return UploadBacklog{Count: count, Bytes: count * 4096, Oldest: time.Now().Add(-oldestAge)}, nil
	}

	return &UploadWorker{
		rdb:         rdb,
		path:        t.TempDir(),
		maxAttempts: 5,
		instanceID:  "mail-07",
	}, rdb
}

// TestMonitorStuckUploads_AlertsOnOldBacklog covers the observability hole around the
// mail-loss path: the uploader deliberately does not count transient S3 errors toward
// max_attempts, so a backlog caused by revoked credentials or a wedged endpoint never
// reaches the attempts >= max_attempts state the failed-upload alert keys on. Age is
// the only signal that state emits, and it is also what the reaper eventually acts on.
func TestMonitorStuckUploads_AlertsOnOldBacklog(t *testing.T) {
	worker, _ := stalledBacklogWorker(t, 6*time.Hour, 1200)
	logs := captureLogs(t)

	if err := worker.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads: %v", err)
	}

	out := logs.String()
	if !strings.Contains(out, "level=WARN") {
		t.Fatalf("a backlog that has not moved in 6h must be reported at WARN, got:\n%s", out)
	}
	if !strings.Contains(out, "instance_id=mail-07") {
		t.Errorf("the alert must name the instance that owns the undelivered bodies, got:\n%s", out)
	}
	if !strings.Contains(out, "oldest_age=6h") {
		t.Errorf("the alert must state how old the backlog is, got:\n%s", out)
	}
	if !strings.Contains(out, "pending=1200") {
		t.Errorf("the alert must state how many uploads are affected, got:\n%s", out)
	}
}

// TestMonitorStuckUploads_HealthyQueueIsNotAlerted keeps the alert credible: a queue
// that is simply being worked through must not warn on every monitor tick.
func TestMonitorStuckUploads_HealthyQueueIsNotAlerted(t *testing.T) {
	worker, _ := stalledBacklogWorker(t, 3*time.Minute, 40)
	logs := captureLogs(t)

	if err := worker.monitorStuckUploads(context.Background()); err != nil {
		t.Fatalf("monitorStuckUploads: %v", err)
	}

	if out := logs.String(); strings.Contains(out, "level=WARN") {
		t.Errorf("a queue that is draining normally must not warn, got:\n%s", out)
	}
}

// TestMonitorStuckUploads_StallAlertDoesNotRepeatEveryTick guards the signal-to-noise
// side: the monitor ticks every 5 minutes and an S3 outage lasts hours, so a per-tick
// warning would bury itself.
func TestMonitorStuckUploads_StallAlertDoesNotRepeatEveryTick(t *testing.T) {
	worker, _ := stalledBacklogWorker(t, 6*time.Hour, 1200)
	logs := captureLogs(t)

	for i := 0; i < 3; i++ {
		if err := worker.monitorStuckUploads(context.Background()); err != nil {
			t.Fatalf("monitorStuckUploads tick %d: %v", i, err)
		}
	}

	if got := strings.Count(logs.String(), "level=WARN"); got != 1 {
		t.Errorf("got %d stall warnings across 3 monitor ticks, want 1:\n%s", got, logs.String())
	}
}

// TestMonitorStuckUploads_StallAlertRepeatsAfterRecovery makes sure the suppression is
// bound to one episode: a queue that drained and then stalls again is new news.
func TestMonitorStuckUploads_StallAlertRepeatsAfterRecovery(t *testing.T) {
	worker, rdb := stalledBacklogWorker(t, 6*time.Hour, 1200)
	logs := captureLogs(t)

	ctx := context.Background()
	if err := worker.monitorStuckUploads(ctx); err != nil {
		t.Fatalf("monitorStuckUploads (stalled): %v", err)
	}

	// S3 comes back and the queue drains.
	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		return UploadBacklog{}, nil
	}
	if err := worker.monitorStuckUploads(ctx); err != nil {
		t.Fatalf("monitorStuckUploads (drained): %v", err)
	}

	// ... and then wedges again.
	rdb.PendingUploadBacklogFunc = func(ctx context.Context, instanceID string, maxAttempts int) (UploadBacklog, error) {
		return UploadBacklog{Count: 7, Bytes: 700, Oldest: time.Now().Add(-4 * time.Hour)}, nil
	}
	if err := worker.monitorStuckUploads(ctx); err != nil {
		t.Fatalf("monitorStuckUploads (stalled again): %v", err)
	}

	if got := strings.Count(logs.String(), "level=WARN"); got != 2 {
		t.Errorf("got %d stall warnings, want one per episode (2):\n%s", got, logs.String())
	}
}
