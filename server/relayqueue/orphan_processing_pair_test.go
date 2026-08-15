package relayqueue

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// CleanupOrphans deletes a half-written pair in pending/ once it is older than
// orphanGracePeriod. A message being delivered is NOT a half-written pair: claimPending
// renames the metadata to processing/ and then the body, and a crash between the two
// renames leaves pending/<id>.msg with its metadata in processing/<id>.json.
//
// That body is the only copy of accepted mail. Judging "orphaned" from the pending
// directory alone reads it as a stray half-write and unlinks it, and os.Rename preserves
// mtime, so a message retried for over an hour is already past the grace period.
// RecoverOrphanedMessages reunites the pair, but only at startup - CleanupOrphans also
// runs on its own ticker, and nothing orders them once the process is up.
func TestCleanupOrphansKeepsABodyWhoseMetadataIsInProcessing(t *testing.T) {
	dir := t.TempDir()
	queue, err := NewDiskQueue(dir, 10, nil)
	if err != nil {
		t.Fatalf("NewDiskQueue: %v", err)
	}

	const id = "msg-mid-claim"
	body := filepath.Join(dir, "pending", id+".msg")
	metadata := filepath.Join(dir, "processing", id+".json")

	if err := os.WriteFile(body, []byte("From: a@example.com\r\n\r\nthe only copy"), 0600); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := os.WriteFile(metadata, []byte(`{"id":"`+id+`"}`), 0600); err != nil {
		t.Fatalf("write metadata: %v", err)
	}

	// Older than the grace period, as any message retried for over an hour would be.
	old := time.Now().Add(-2 * orphanGracePeriod)
	if err := os.Chtimes(body, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	if _, err := queue.CleanupOrphans(); err != nil {
		t.Fatalf("CleanupOrphans: %v", err)
	}

	if _, err := os.Stat(body); os.IsNotExist(err) {
		t.Error("CleanupOrphans deleted the message body while its metadata was in processing/: " +
			"that body is the only copy of an accepted message")
	} else if err != nil {
		t.Fatalf("stat body: %v", err)
	}
}

// TestCleanupOrphansStillRemovesATrueHalfWrite keeps the sweep doing its job: a body with
// no metadata anywhere really is a stray half-write and must still be reclaimed.
func TestCleanupOrphansStillRemovesATrueHalfWrite(t *testing.T) {
	dir := t.TempDir()
	queue, err := NewDiskQueue(dir, 10, nil)
	if err != nil {
		t.Fatalf("NewDiskQueue: %v", err)
	}

	body := filepath.Join(dir, "pending", "stray.msg")
	if err := os.WriteFile(body, []byte("orphan"), 0600); err != nil {
		t.Fatalf("write body: %v", err)
	}
	old := time.Now().Add(-2 * orphanGracePeriod)
	if err := os.Chtimes(body, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	removed, err := queue.CleanupOrphans()
	if err != nil {
		t.Fatalf("CleanupOrphans: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed %d files, want 1", removed)
	}
	if _, err := os.Stat(body); !os.IsNotExist(err) {
		t.Error("a body with no metadata anywhere was not reclaimed")
	}
}
