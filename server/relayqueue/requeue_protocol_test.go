//go:build unix

package relayqueue

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This helper is a real second process: killing it releases its advisory lease.
// Only the publication sync seam pauses the writer; the parent uses public queue
// operations against the same spool, not a second in-process mutex.
func TestRelayQueueProtocolProcess(t *testing.T) {
	mode := os.Getenv("SORA_RELAY_PROTOCOL_MODE")
	if mode == "" {
		return
	}
	q, err := NewDiskQueue(os.Getenv("SORA_RELAY_PROTOCOL_DIR"), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := os.Getenv("SORA_RELAY_PROTOCOL_ID")
	pause := func() { fmt.Println("RELAY-PROTOCOL-READY"); _, _ = io.Copy(io.Discard, os.Stdin) }
	switch mode {
	case "requeue":
		real := syncDir
		syncDir = func(dir string) error {
			if dir == q.pendingDir && fileExists(filepath.Join(dir, id+".json")) {
				pause()
			}
			return real(dir)
		}
		if err := q.Requeue(id); err != nil {
			t.Fatal(err)
		}
	case "claim":
		msg, _, err := q.AcquireNext()
		if err != nil || msg == nil {
			t.Fatalf("claim: %v %v", msg, err)
		}
		pause()
	case "complete", "discard":
		var msg *QueuedMessage
		if mode == "complete" {
			msg, _, err = q.AcquireNext()
		} else {
			msg = &QueuedMessage{ID: id}
		}
		if err != nil || msg == nil {
			t.Fatalf("claim: %v %v", msg, err)
		}
		real := syncDir
		syncDir = func(dir string) error {
			if err := real(dir); err != nil {
				return err
			}
			if dir == q.failedDir {
				data, _ := os.ReadFile(filepath.Join(dir, ".transaction-"+msg.ID+".state"))
				var state struct {
					Phase string `json:"phase"`
				}
				_ = json.Unmarshal(data, &state)
				if state.Phase == "complete" {
					pause()
				}
			}
			return nil
		}
		if mode == "complete" {
			err = q.MarkSuccess(msg.ID)
		} else {
			err = q.Delete(msg.ID, "failed")
		}
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown child mode")
	}
}
func protocolChild(t *testing.T, q *DiskQueue, id, mode string) func() {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRelayQueueProtocolProcess$", "-test.timeout=30s")
	cmd.Env = append(os.Environ(), "SORA_RELAY_PROTOCOL_MODE="+mode, "SORA_RELAY_PROTOCOL_DIR="+q.basePath, "SORA_RELAY_PROTOCOL_ID="+id)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			_ = cmd.Process.Kill()
			_ = in.Close()
			_ = cmd.Wait()
		}
	}
	t.Cleanup(stop)
	ready := make(chan error, 1)
	go func() {
		s := bufio.NewScanner(out)
		for s.Scan() {
			if strings.TrimSpace(s.Text()) == "RELAY-PROTOCOL-READY" {
				ready <- nil
				return
			}
		}
		ready <- fmt.Errorf("child exited before barrier: %v", s.Err())
	}()
	select {
	case err := <-ready:
		if err != nil {
			stop()
			t.Fatalf("%v; %s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		stop()
		t.Fatalf("child barrier timeout; %s", stderr.String())
	}
	return stop
}
func TestRequeueLiveProcessIsNotRecoveredByAge(t *testing.T) {
	q, err := NewDiskQueue(t.TempDir(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := failMessage(t, q, "recipient@example.com", "550 rejected")
	stop := protocolChild(t, q, id, "requeue")
	old := time.Now().Add(-2 * orphanGracePeriod)
	for _, dir := range []string{q.failedDir, q.pendingDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if err := os.Chtimes(filepath.Join(dir, e.Name()), old, old); err != nil {
				t.Fatal(err)
			}
		}
	}
	oldMeta := filepath.Join(q.failedDir, requeueRetiringPrefix+id+requeueRetiringJSON)
	oldBody := filepath.Join(q.failedDir, requeueRetiringPrefix+id+requeueRetiringMsg)
	if _, err := q.CleanupOrphans(); err != nil {
		t.Fatal(err)
	}
	if n, err := q.RecoverOrphanedMessages(); err != nil || n != 0 {
		t.Fatalf("live recovery: %d %v", n, err)
	}
	if !fileExists(oldMeta) || !fileExists(oldBody) {
		t.Fatal("cleanup consumed an active requeue's retired pair")
	}
	q.pending.invalidate()
	if msg, _, err := q.AcquireNext(); err != nil || msg != nil {
		t.Fatalf("worker acquired live publication: %v %v", msg, err)
	}
	stop()
	if _, err := q.RecoverOrphanedMessages(); err != nil {
		t.Fatal(err)
	}
	q.pending.invalidate()
	msg, body, err := q.AcquireNext()
	if err != nil || msg == nil || len(body) == 0 {
		t.Fatalf("dead publisher recovery: %v %q %v", msg, body, err)
	}
	if err := q.MarkSuccess(msg.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := q.RecoverOrphanedMessages(); err != nil {
		t.Fatal(err)
	}
	assertEmptyProtocolQueue(t, q)
}
func TestRecoveryDoesNotStealLiveDelivery(t *testing.T) {
	q, err := NewDiskQueue(t.TempDir(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue("from@example.com", "to@example.com", "redirect", []byte("body")); err != nil {
		t.Fatal(err)
	}
	stop := protocolChild(t, q, "", "claim")
	if n, err := q.RecoverOrphanedMessages(); err != nil || n != 0 {
		t.Fatalf("live delivery recovered: %d %v", n, err)
	}
	if msg, _, err := q.AcquireNext(); err != nil || msg != nil {
		t.Fatalf("duplicate live delivery: %v %v", msg, err)
	}
	stop()
	if n, err := q.RecoverOrphanedMessages(); err != nil || n != 1 {
		t.Fatalf("dead delivery recovery: %d %v", n, err)
	}
	q.pending.invalidate()
	msg, _, err := acquireProtocolEventually(t, q)
	if err != nil || msg == nil {
		t.Fatalf("retry: %v %v", msg, err)
	}
	if err := q.MarkSuccess(msg.ID); err != nil {
		t.Fatal(err)
	}
}
func TestTerminalSuccessSurvivesProcessDeath(t *testing.T) {
	q, err := NewDiskQueue(t.TempDir(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue("from@example.com", "to@example.com", "redirect", []byte("body")); err != nil {
		t.Fatal(err)
	}
	stop := protocolChild(t, q, "", "complete")
	stop()
	if _, err := q.RecoverOrphanedMessages(); err != nil {
		t.Fatal(err)
	}
	assertEmptyProtocolQueue(t, q)
	if msg, _, err := q.AcquireNext(); err != nil || msg != nil {
		t.Fatalf("completed mail was redelivered: %v %v", msg, err)
	}
}
func assertEmptyProtocolQueue(t *testing.T, q *DiskQueue) {
	t.Helper()
	p, w, f, err := q.GetStats()
	if err != nil || p != 0 || w != 0 || f != 0 {
		t.Fatalf("queue state pending=%d processing=%d failed=%d err=%v", p, w, f, err)
	}
}
func TestRequeueRollbackFailureRetainsRetryablePair(t *testing.T) {
	q, err := NewDiskQueue(t.TempDir(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := failMessage(t, q, "to@example.com", "550 rejected")
	var m QueuedMessage
	if err := q.readMetadata(filepath.Join(q.failedDir, id+".json"), &m); err != nil {
		t.Fatal(err)
	}
	a, b, _ := q.retiredPaths(id)
	for _, p := range [][2]string{{filepath.Join(q.failedDir, id+".json"), a}, {filepath.Join(q.failedDir, id+".msg"), b}} {
		if err := os.Rename(p[0], p[1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.writeState(requeueState{Phase: "rollback", Metadata: m}); err != nil {
		t.Fatal(err)
	}
	obstruction := filepath.Join(q.failedDir, id+".msg")
	if err := os.Mkdir(obstruction, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := q.RecoverOrphanedMessages(); err == nil {
		t.Fatal("body restore failure was ignored")
	}
	for _, p := range []string{a, b, q.journalPath(id)} {
		if !fileExists(p) {
			t.Fatalf("restore lost retry evidence %s", p)
		}
	}
	if err := os.Remove(obstruction); err != nil {
		t.Fatal(err)
	}
	if _, err := q.RecoverOrphanedMessages(); err != nil {
		t.Fatal(err)
	}
	for _, ext := range []string{".msg", ".json"} {
		if !fileExists(filepath.Join(q.failedDir, id+ext)) {
			t.Fatal("restoration incomplete")
		}
	}
}
func TestRequeuePublicationFailureCannotResurrectDeliveredMail(t *testing.T) {
	dir := t.TempDir()
	admin, err := NewDiskQueue(dir, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := NewDiskQueue(dir, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := failMessage(t, admin, "to@example.com", "550 rejected")
	real := syncDir
	defer func() { syncDir = real }()
	injected := false
	syncDir = func(dir string) error {
		if !injected && dir == admin.pendingDir && fileExists(filepath.Join(dir, id+".json")) {
			injected = true
			worker.pending.invalidate()
			if msg, _, err := worker.AcquireNext(); err != nil || msg != nil {
				t.Fatalf("delivered before durable handoff: %v %v", msg, err)
			}
			return errors.New("publication sync fault")
		}
		return real(dir)
	}
	if err := admin.Requeue(id); err == nil || !injected {
		t.Fatalf("fault was not exercised: %v", err)
	}
	syncDir = real
	if _, err := worker.RecoverOrphanedMessages(); err != nil {
		t.Fatal(err)
	}
	worker.pending.invalidate()
	msg, _, err := worker.AcquireNext()
	if err != nil || msg == nil {
		t.Fatalf("recovered claim: %v %v", msg, err)
	}
	if err := worker.MarkSuccess(msg.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := worker.RecoverOrphanedMessages(); err != nil {
		t.Fatal(err)
	}
	assertEmptyProtocolQueue(t, worker)
}
func TestLegacyRequeueAbsenceIsNotPublicationEvidence(t *testing.T) {
	q, err := NewDiskQueue(t.TempDir(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := failMessage(t, q, "to@example.com", "550 rejected")
	a, b, _ := q.retiredPaths(id)
	for _, p := range [][2]string{{filepath.Join(q.failedDir, id+".json"), a}, {filepath.Join(q.failedDir, id+".msg"), b}} {
		if err := os.Rename(p[0], p[1]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := q.RecoverOrphanedMessages(); err == nil {
		t.Fatal("legacy ambiguous requeue was silently interpreted")
	}
	if !fileExists(a) || !fileExists(b) {
		t.Fatal("ambiguous body evidence was deleted")
	}
	assertEmptyProtocolQueue(t, q)
}

func TestRecoveryKeepsPublishedFailureMetadata(t *testing.T) {
	for _, permanent := range []bool{false, true} {
		t.Run(fmt.Sprintf("permanent=%v", permanent), func(t *testing.T) {
			q, err := NewDiskQueue(t.TempDir(), 10, []time.Duration{time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			if err := q.Enqueue("from@example.com", "to@example.com", "redirect", []byte("same-body")); err != nil {
				t.Fatal(err)
			}
			msg, _, err := q.AcquireNext()
			if err != nil || msg == nil {
				t.Fatalf("claim: %v %v", msg, err)
			}
			target := q.pendingDir
			if permanent {
				target = q.failedDir
			}
			real := syncDir
			injected := false
			syncDir = func(dir string) error {
				if !injected && dir == target && fileExists(filepath.Join(dir, msg.ID+".json")) {
					injected = true
					return errors.New("destination metadata sync failure")
				}
				return real(dir)
			}
			if permanent {
				err = q.MarkPermanentFailure(msg.ID, "550 denied")
			} else {
				err = q.MarkFailure(msg.ID, "451 retry")
			}
			syncDir = real
			if err == nil || !injected {
				t.Fatalf("failure cut not exercised: %v", err)
			}
			if _, err := q.RecoverOrphanedMessages(); err != nil {
				t.Fatal(err)
			}
			var after QueuedMessage
			if err := q.readMetadata(filepath.Join(target, msg.ID+".json"), &after); err != nil {
				t.Fatal(err)
			}
			if after.Attempts != 1 || len(after.Errors) != 1 {
				t.Fatalf("new failure metadata overwritten: %+v", after)
			}
			body, err := os.ReadFile(filepath.Join(target, msg.ID+".msg"))
			if err != nil || string(body) != "same-body" {
				t.Fatalf("destination body: %q %v", body, err)
			}
			if !permanent && time.Until(after.NextRetry) < 50*time.Minute {
				t.Fatalf("retry backoff lost: %+v", after)
			}
			if next, _, err := q.AcquireNext(); err != nil || next != nil {
				t.Fatalf("failure immediately redelivered: %v %v", next, err)
			}
		})
	}
}

func TestDeleteRefusesLiveWorkerAndRequeue(t *testing.T) {
	for _, mode := range []string{"claim", "requeue"} {
		t.Run(mode, func(t *testing.T) {
			q, err := NewDiskQueue(t.TempDir(), 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			var id, queue string
			if mode == "requeue" {
				id = failMessage(t, q, "to@example.com", "550 failed")
				queue = "pending"
			} else {
				if err := q.Enqueue("from@example.com", "to@example.com", "redirect", []byte("body")); err != nil {
					t.Fatal(err)
				}
				entries, err := os.ReadDir(q.pendingDir)
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range entries {
					if strings.HasSuffix(e.Name(), ".json") {
						id = strings.TrimSuffix(e.Name(), ".json")
					}
				}
				queue = "processing"
			}
			stop := protocolChild(t, q, id, mode)
			if err := q.Delete(id, queue); err == nil || !strings.Contains(err.Error(), "busy") {
				t.Fatalf("live operation not protected from discard: %v", err)
			}
			if !fileExists(filepath.Join(q.basePath, queue, id+".json")) {
				t.Fatal("busy discard removed message")
			}
			stop()
			if err := q.Delete(id, queue); err != nil {
				t.Fatal(err)
			}
			if _, err := q.RecoverOrphanedMessages(); err != nil {
				t.Fatal(err)
			}
			assertEmptyProtocolQueue(t, q)
		})
	}
}
func TestDiscardDecisionSurvivesProcessDeath(t *testing.T) {
	q, err := NewDiskQueue(t.TempDir(), 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := failMessage(t, q, "to@example.com", "550 failed")
	stop := protocolChild(t, q, id, "discard")
	stop()
	if _, err := q.RecoverOrphanedMessages(); err != nil {
		t.Fatal(err)
	}
	assertEmptyProtocolQueue(t, q)
}

// Fail each directory-sync boundary once. The recovery result must be exactly
// one recoverable failed message or one published message, never a detached pair.
func TestRequeueEverySyncBoundaryRecoversOneCopy(t *testing.T) {
	for cut := 1; cut <= 9; cut++ {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			q, err := NewDiskQueue(t.TempDir(), 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			id := failMessage(t, q, "to@example.com", "550 failed")
			real := syncDir
			n := 0
			syncDir = func(dir string) error {
				n++
				if n == cut {
					return errors.New("requeue sync cut")
				}
				return real(dir)
			}
			err = q.Requeue(id)
			syncDir = real
			if err == nil || n < cut {
				t.Fatalf("sync cut not reached: n=%d err=%v", n, err)
			}
			if _, err := q.RecoverOrphanedMessages(); err != nil {
				t.Fatal(err)
			}
			pending, processing, failed, err := q.GetStats()
			if err != nil || processing != 0 || pending+failed != 1 {
				t.Fatalf("recovery copies: %d/%d/%d %v", pending, processing, failed, err)
			}
			if failed == 1 {
				if err := q.Requeue(id); err != nil {
					t.Fatal(err)
				}
			}
			q.pending.invalidate()
			msg, body, err := q.AcquireNext()
			if err != nil || msg == nil || len(body) == 0 {
				t.Fatalf("recovered body: %v %q %v", msg, body, err)
			}
			if err := q.MarkSuccess(msg.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := q.RecoverOrphanedMessages(); err != nil {
				t.Fatal(err)
			}
			assertEmptyProtocolQueue(t, q)
		})
	}
}
func TestTerminalEverySyncFailureDoesNotResend(t *testing.T) {
	for cut := 1; cut <= 6; cut++ {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			q, err := NewDiskQueue(t.TempDir(), 1, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := q.Enqueue("from@example.com", "to@example.com", "redirect", []byte("body")); err != nil {
				t.Fatal(err)
			}
			msg, _, err := q.AcquireNext()
			if err != nil || msg == nil {
				t.Fatalf("claim: %v %v", msg, err)
			}
			real := syncDir
			n := 0
			syncDir = func(dir string) error {
				n++
				if n == cut {
					return errors.New("terminal sync cut")
				}
				return real(dir)
			}
			err = q.MarkSuccess(msg.ID)
			syncDir = real
			if err == nil || n < cut {
				t.Fatalf("terminal sync cut not reached: n=%d err=%v", n, err)
			}
			if _, err := q.RecoverOrphanedMessages(); err != nil {
				t.Fatal(err)
			}
			assertEmptyProtocolQueue(t, q)
			if next, _, err := q.AcquireNext(); err != nil || next != nil {
				t.Fatalf("completed mail resent after cleanup failure: %v %v", next, err)
			}
		})
	}
}
