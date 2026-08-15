package relayqueue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAcquireCostDoesNotScaleWithBacklog pins the cost of taking one message off the
// queue to something independent of how much mail is already queued. With the relay
// circuit breaker open nothing drains, so the backlog is exactly what grows - and it
// must not turn every acquire into a fresh parse of the whole pending directory.
func TestAcquireCostDoesNotScaleWithBacklog(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	const backlog = 200
	const acquires = 20

	// The backlog is not due yet and sorts ahead of the deliverable messages, so a
	// directory scan has to walk and parse all of it before reaching anything useful.
	notDue := time.Now().Add(1 * time.Hour)
	for i := 0; i < backlog; i++ {
		writePendingMessage(t, queue, fmt.Sprintf("backlog-%04d", i), notDue)
	}
	due := time.Now().Add(-1 * time.Minute)
	for i := 0; i < acquires; i++ {
		writePendingMessage(t, queue, fmt.Sprintf("ready-%04d", i), due)
	}

	var reads atomic.Int64
	queue.metaRead = func() { reads.Add(1) }

	for i := 0; i < acquires; i++ {
		msg, _, err := queue.AcquireNext()
		if err != nil {
			t.Fatalf("AcquireNext %d failed: %v", i+1, err)
		}
		if msg == nil {
			t.Fatalf("Expected a message on acquire %d, got nil", i+1)
		}
	}

	// One pass over the directory, plus a constant number of reads per acquisition.
	limit := int64(backlog + 4*acquires)
	if got := reads.Load(); got > limit {
		t.Errorf("Acquiring %d messages behind a backlog of %d read %d metadata files, want at most %d: the acquire path re-parses the backlog on every call",
			acquires, backlog, got, limit)
	}
}

// TestEnqueueDoesNotWaitForPendingScan holds a pending-directory scan open and requires
// an enqueue to complete while it is still running. Enqueue is on the LMTP delivery
// path, so anything it waits on delays accepting inbound mail; it must not wait on work
// whose size is the relay backlog.
func TestEnqueueDoesNotWaitForPendingScan(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	for i := 0; i < 3; i++ {
		writePendingMessage(t, queue, fmt.Sprintf("backlog-%04d", i), time.Now().Add(1*time.Hour))
	}

	scanning := make(chan struct{})
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })

	var gate sync.Once
	queue.metaRead = func() {
		gate.Do(func() {
			close(scanning)
			<-release
		})
	}

	var acquireErr error
	var acquiring sync.WaitGroup
	acquiring.Add(1)
	go func() {
		defer acquiring.Done()
		_, _, acquireErr = queue.AcquireNext()
	}()
	// Let the scan finish even if the test fails below, so it cannot outlive TempDir.
	t.Cleanup(func() {
		releaseOnce()
		acquiring.Wait()
	})

	<-scanning

	enqueued := make(chan error, 1)
	go func() {
		enqueued <- queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("new mail"))
	}()

	select {
	case err := <-enqueued:
		if err != nil {
			t.Fatalf("Enqueue failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Enqueue blocked behind an in-progress pending scan: relay backlog stalls inbound mail")
	}

	releaseOnce()
	acquiring.Wait()
	if acquireErr != nil {
		t.Fatalf("AcquireNext failed: %v", acquireErr)
	}
}

// TestRestartedQueueFindsMailOnlyOnDisk covers what an in-memory pending index could
// otherwise lose: a restarted process starts with no index, so everything the previous
// one left in the queue - including what crash recovery moves back out of processing/ -
// has to be rediscovered from the directory, and delivered exactly once.
func TestRestartedQueueFindsMailOnlyOnDisk(t *testing.T) {
	dir := t.TempDir()

	crashed, err := NewDiskQueue(dir, 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}
	body := []byte("Subject: Redirect\r\n\r\ndeliver me")
	if err := crashed.Enqueue("sender@example.com", "recipient@example.com", "redirect", body); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}
	acquired, _, err := crashed.AcquireNext()
	if err != nil || acquired == nil {
		t.Fatalf("AcquireNext failed: %v", err)
	}
	// The process dies here, with the message sitting in processing/.

	restarted, err := NewDiskQueue(dir, 10, nil)
	if err != nil {
		t.Fatalf("Failed to reopen queue: %v", err)
	}
	recovered, err := restarted.RecoverOrphanedMessages()
	if err != nil {
		t.Fatalf("RecoverOrphanedMessages failed: %v", err)
	}
	if recovered != 1 {
		t.Fatalf("Expected 1 recovered message, got %d", recovered)
	}

	msg, msgBytes, err := restarted.AcquireNext()
	if err != nil {
		t.Fatalf("AcquireNext after restart failed: %v", err)
	}
	if msg == nil {
		t.Fatal("Expected the recovered message to be acquired after restart, got nil")
	}
	if msg.ID != acquired.ID {
		t.Errorf("Expected message %s, got %s", acquired.ID, msg.ID)
	}
	if string(msgBytes) != string(body) {
		t.Errorf("Expected body %q, got %q", body, msgBytes)
	}

	again, _, err := restarted.AcquireNext()
	if err != nil {
		t.Fatalf("Second AcquireNext failed: %v", err)
	}
	if again != nil {
		t.Errorf("Expected the message to be acquired once, got it again as %s", again.ID)
	}
}

// TestResyncPicksUpMessagesQueuedOutOfBand covers `sora-admin relay requeue`, which
// moves a message into pending/ from a separate process while the server is running.
// The index only learns about it on its periodic rebuild.
func TestResyncPicksUpMessagesQueuedOutOfBand(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	if msg, _, err := queue.AcquireNext(); err != nil || msg != nil {
		t.Fatalf("Expected an empty queue, got msg=%v err=%v", msg, err)
	}

	writePendingMessage(t, queue, "requeued-0001", time.Now().Add(-1*time.Minute))
	queue.pending.invalidate() // stand in for pendingResyncInterval elapsing

	msg, _, err := queue.AcquireNext()
	if err != nil {
		t.Fatalf("AcquireNext failed: %v", err)
	}
	if msg == nil {
		t.Fatal("Expected the out-of-band message to be picked up by the resync, got nil")
	}
	if msg.ID != "requeued-0001" {
		t.Errorf("Expected message requeued-0001, got %s", msg.ID)
	}
}

// writePendingMessage drops a message pair straight into the pending directory. It is
// faster than Enqueue and lets a test control both the ID (and thus directory order)
// and the retry time.
func writePendingMessage(t *testing.T, queue *DiskQueue, id string, nextRetry time.Time) {
	t.Helper()

	metadata := QueuedMessage{
		ID:        id,
		From:      "sender@example.com",
		To:        "recipient@example.com",
		Type:      "redirect",
		QueuedAt:  time.Now(),
		NextRetry: nextRetry,
		Errors:    []string{},
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Failed to marshal metadata for %s: %v", id, err)
	}

	if err := os.WriteFile(filepath.Join(queue.pendingDir, id+".msg"), []byte("Subject: Test\r\n\r\n"+id), 0644); err != nil {
		t.Fatalf("Failed to write body for %s: %v", id, err)
	}
	if err := os.WriteFile(filepath.Join(queue.pendingDir, id+".json"), data, 0644); err != nil {
		t.Fatalf("Failed to write metadata for %s: %v", id, err)
	}
}
