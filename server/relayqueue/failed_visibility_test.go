package relayqueue

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// logCapture collects the process logger's output for the duration of a test.
// The buffer is mutex-guarded: the worker logs from its own goroutines.
type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(p)
}

// warnLines returns the captured WARN records, one per line.
func (c *logCapture) warnLines() []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var warns []string
	for _, line := range strings.Split(c.buf.String(), "\n") {
		if strings.Contains(line, "level=WARN") {
			warns = append(warns, line)
		}
	}
	return warns
}

// captureLogs redirects the logger for the duration of the test. The logger package
// falls back to slog.Default when it has not been initialized, which is the case in
// unit tests.
func captureLogs(t *testing.T) *logCapture {
	t.Helper()

	capture := &logCapture{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(capture, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return capture
}

// failMessage runs one message through to the failed directory and returns its ID.
func failMessage(t *testing.T, queue *DiskQueue, to, errorMsg string) string {
	t.Helper()

	if err := queue.Enqueue("sender@example.com", to, "redirect", []byte("Subject: Forwarded\r\n\r\nbody")); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}
	msg, _, err := queue.AcquireNext()
	if err != nil {
		t.Fatalf("AcquireNext failed: %v", err)
	}
	if msg == nil {
		t.Fatal("Expected to acquire the message just enqueued")
	}
	if err := queue.MarkPermanentFailure(msg.ID, errorMsg); err != nil {
		t.Fatalf("MarkPermanentFailure failed: %v", err)
	}
	return msg.ID
}

// TestPeriodicCleanupWarnsAboutFailedMessages covers the only notice an operator
// gets about mail the relay gave up on. A Sieve redirect without :copy is accepted
// with 250 and never stored locally, so a message in failed/ is the only copy left;
// it sits there until the retention purge deletes it. The periodic maintenance pass
// must therefore name what is waiting - count, age of the oldest, and why it failed -
// rather than leaving the queue discoverable only by reading the disk.
func TestPeriodicCleanupWarnsAboutFailedMessages(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	failMessage(t, queue, "first@example.com", "550 5.1.1 recipient rejected")
	failMessage(t, queue, "second@example.com", "550 5.7.1 message refused")

	worker := NewWorker(queue, &mockRelayHandler{}, time.Minute, 10, 1, time.Hour, 168*time.Hour, nil)

	capture := captureLogs(t)
	worker.runCleanup()

	for _, line := range capture.warnLines() {
		if strings.Contains(line, "count=2") && strings.Contains(line, "oldest_age=") && strings.Contains(line, "550") {
			return
		}
	}

	t.Fatalf("periodic cleanup produced no WARN naming the failed queue (count, oldest age, last error); captured warnings: %q\n"+
		"Two permanently failed redirects are sitting in failed/ as the only copy of that mail, and the retention purge will "+
		"delete them in 168h0m0s. Without a warning an operator has no reason to run sora-admin relay list before that happens.",
		capture.warnLines())
}

// TestRetentionPurgeWarnsPerDeletedMessage covers the moment the last copy of a
// forwarded message is destroyed. The purge is routine maintenance, but what it
// deletes is mail that was accepted with a 250, so each deletion must be recorded
// loudly enough to be found afterwards - with the recipient and the failure reason,
// not just a count.
func TestRetentionPurgeWarnsPerDeletedMessage(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	id := failMessage(t, queue, "forwardee@example.com", "550 5.1.1 recipient rejected")
	ageFailedMessage(t, queue, id, time.Now().Add(-8*24*time.Hour))

	capture := captureLogs(t)
	cleaned, err := queue.CleanupOldFailedMessages(168 * time.Hour)
	if err != nil {
		t.Fatalf("CleanupOldFailedMessages failed: %v", err)
	}
	if cleaned != 1 {
		t.Fatalf("Expected 1 message purged, got %d", cleaned)
	}

	for _, line := range capture.warnLines() {
		if strings.Contains(line, id) && strings.Contains(line, "forwardee@example.com") {
			return
		}
	}

	t.Fatalf("retention purge deleted a permanently failed message without a WARN naming it; captured warnings: %q\n"+
		"That file was the only copy of a message the server accepted with 250 and forwarded nowhere. "+
		"Deleting it at info level leaves no record an operator would notice.",
		capture.warnLines())
}

// TestQueueDepthMetricsRefreshWithoutTraffic covers the alerting path. The failed
// queue only grows when deliveries fail, and once the pending queue drains there is
// nothing left to process - so a depth gauge that is only written while messages are
// being processed goes stale exactly when the failed count matters.
func TestQueueDepthMetricsRefreshWithoutTraffic(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	failMessage(t, queue, "first@example.com", "550 5.1.1 recipient rejected")
	failMessage(t, queue, "second@example.com", "550 5.7.1 message refused")

	metrics.RelayQueueDepth.Reset()

	worker := NewWorker(queue, &mockRelayHandler{}, time.Minute, 10, 1, time.Hour, 168*time.Hour, nil)
	if err := worker.processQueue(context.Background()); err != nil {
		t.Fatalf("processQueue failed: %v", err)
	}

	if got := testutil.ToFloat64(metrics.RelayQueueDepth.WithLabelValues("failed")); got != 2 {
		t.Fatalf("sora_relay_queue_depth{state=\"failed\"} = %v after a cycle with nothing to deliver, want 2: "+
			"the gauge is only written when a message was processed, so the failed queue is invisible to alerting "+
			"once the pending queue is empty", got)
	}
}

// ageFailedMessage backdates the last-attempt timestamp of a failed message, which
// is what the retention purge measures.
func ageFailedMessage(t *testing.T, queue *DiskQueue, messageID string, lastAttempt time.Time) {
	t.Helper()

	path := filepath.Join(queue.failedDir, messageID+".json")
	var metadata QueuedMessage
	if err := queue.readMetadata(path, &metadata); err != nil {
		t.Fatalf("Failed to read failed metadata: %v", err)
	}
	metadata.LastAttempt = lastAttempt
	if err := queue.writeFileAtomic(path, metadata); err != nil {
		t.Fatalf("Failed to rewrite failed metadata: %v", err)
	}
}
