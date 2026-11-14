package relayqueue

import (
	"path/filepath"
	"testing"
)

// TestRequeueConcurrentPermanentFailureDoesNotLoseMessage reproduces the cross-process
// race between `sora-admin relay requeue` (adminQ) and the running server's relay worker
// (serverQ): as soon as Requeue publishes pending/<id>.json, the server worker can
// acquire <id> and fail it permanently back into failed/<id>.{msg,json} before Requeue
// finishes removing the old failed/<id>.{msg,json} pair. Requeue must never delete the
// newly failed message.
func TestRequeueConcurrentPermanentFailureDoesNotLoseMessage(t *testing.T) {
	dir := t.TempDir()
	serverQ, err := NewDiskQueue(dir, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	adminQ, err := NewDiskQueue(dir, 1, nil)
	if err != nil {
		t.Fatal(err)
	}

	id := failMessage(t, serverQ, "recipient@example.com", "550 5.1.1 initial permanent failure")
	pendingMeta := filepath.Join(dir, "pending", id+".json")

	realSyncDir := syncDir
	t.Cleanup(func() { syncDir = realSyncDir })
	workerRan := false
	syncDir = func(d string) error {
		err := realSyncDir(d)
		if !workerRan && d == adminQ.pendingDir && fileExists(pendingMeta) {
			workerRan = true
			serverQ.pending.invalidate()
			msg, _, acqErr := serverQ.AcquireNext()
			if acqErr != nil || msg == nil {
				t.Fatalf("worker AcquireNext after pending/%s.json appeared: msg=%v err=%v", id, msg, acqErr)
			}
			if failErr := serverQ.MarkPermanentFailure(msg.ID, "550 5.1.1 still rejected"); failErr != nil {
				t.Fatalf("worker MarkPermanentFailure: %v", failErr)
			}
		}
		return err
	}

	if err := adminQ.Requeue(id); err != nil {
		t.Fatalf("Requeue: %v", err)
	}
	if !workerRan {
		t.Fatal("worker seam did not fire when pending/<id>.json became visible")
	}

	pending, processing, failed, err := serverQ.GetStats()
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if failed != 1 || pending != 0 || processing != 0 {
		t.Fatalf("message %s lost after concurrent permanent failure: pending=%d processing=%d failed=%d (want pending=0 processing=0 failed=1)",
			id, pending, processing, failed)
	}
	if !fileExists(filepath.Join(dir, "failed", id+".msg")) || !fileExists(filepath.Join(dir, "failed", id+".json")) {
		t.Fatalf("failed/%s.{msg,json} missing after concurrent permanent failure", id)
	}
	var got QueuedMessage
	if err := serverQ.readMetadata(filepath.Join(dir, "failed", id+".json"), &got); err != nil {
		t.Fatalf("readMetadata: %v", err)
	}
	if got.Attempts != 1 || lastError(got) == "" {
		t.Fatalf("unexpected failed metadata after second failure: %+v", got)
	}
}
