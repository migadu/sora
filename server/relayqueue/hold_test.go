package relayqueue

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pendingFiles lists the names in the pending directory.
func pendingFiles(t *testing.T, q *DiskQueue) []string {
	t.Helper()
	entries, err := os.ReadDir(q.pendingDir)
	if err != nil {
		t.Fatalf("read pending: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestHoldInvisibleUntilCommit: a held message is on disk but the worker cannot take
// it, not even after a resync of the pending directory, until it is committed.
func TestHoldInvisibleUntilCommit(t *testing.T) {
	q, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	commit, abort, err := q.Hold("from@example.com", "to@example.org", "redirect", []byte("held body"))
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	defer abort()

	q.pending.invalidate() // force AcquireNext to rescan the directory
	if msg, _, err := q.AcquireNext(); err != nil || msg != nil {
		t.Fatalf("AcquireNext before commit = %v, %v; want nothing", msg, err)
	}
	if pending, _, _, err := q.GetStats(); err != nil || pending != 0 {
		t.Fatalf("pending before commit = %d, %v; want 0", pending, err)
	}

	if err := commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	abort() // after commit: does nothing
	msg, body, err := q.AcquireNext()
	if err != nil || msg == nil {
		t.Fatalf("AcquireNext after commit = %v, %v; want the message", msg, err)
	}
	if msg.From != "from@example.com" || msg.To != "to@example.org" || msg.Type != "redirect" || string(body) != "held body" {
		t.Errorf("acquired %+v with body %q", msg, body)
	}
}

// TestHoldAbort: an aborted hold leaves nothing in the queue, and cannot be committed.
func TestHoldAbort(t *testing.T) {
	q, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	commit, abort, err := q.Hold("from@example.com", "to@example.org", "redirect", []byte("held body"))
	if err != nil {
		t.Fatalf("Hold: %v", err)
	}
	if files := pendingFiles(t, q); len(files) != 2 {
		t.Fatalf("pending holds %v, want the body and its held metadata", files)
	}

	abort()
	if files := pendingFiles(t, q); len(files) != 0 {
		t.Errorf("pending holds %v after abort, want nothing", files)
	}
	if err := commit(); err == nil {
		t.Error("commit after abort succeeded")
	}
	q.pending.invalidate()
	if msg, _, err := q.AcquireNext(); err != nil || msg != nil {
		t.Errorf("AcquireNext after abort = %v, %v; want nothing", msg, err)
	}
}

// TestCleanupOrphansRemovesDeadHold: a hold whose process died before commit or abort
// is removed once its grace period is over; one still within it is left alone.
func TestCleanupOrphansRemovesDeadHold(t *testing.T) {
	q, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := q.Hold("from@example.com", "dead@example.org", "redirect", []byte("dead")); err != nil {
		t.Fatalf("Hold: %v", err)
	}
	old := time.Now().Add(-2 * orphanGracePeriod)
	for _, name := range pendingFiles(t, q) {
		if err := os.Chtimes(filepath.Join(q.pendingDir, name), old, old); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := q.Hold("from@example.com", "live@example.org", "redirect", []byte("live")); err != nil {
		t.Fatalf("Hold: %v", err)
	}

	removed, err := q.CleanupOrphans()
	if err != nil {
		t.Fatalf("CleanupOrphans: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed %d files, want the dead hold's body and metadata (2)", removed)
	}
	if files := pendingFiles(t, q); len(files) != 2 {
		t.Errorf("pending holds %v, want the live hold's two files", files)
	}
}
