package relayqueue

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/migadu/sora/logger"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const requeueJournalPrefix = ".transaction-"
const requeueJournalSuffix = ".state"

// Preparing is rolled back; publishing is rolled forward. Published is never
// interpreted as unpublished merely because queue files are absent. Complete is
// persisted before a successful delivery's files are removed.
type requeueState struct {
	Version  int           `json:"version"`
	Phase    string        `json:"phase"`
	Discard  bool          `json:"discard,omitempty"`
	Metadata QueuedMessage `json:"metadata"`
}

func (q *DiskQueue) journalPath(id string) string {
	return filepath.Join(q.failedDir, requeueJournalPrefix+id+requeueJournalSuffix)
}
func (q *DiskQueue) writeState(s requeueState) error {
	s.Version = 1
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	owner, err := foreignOwner(q.failedDir)
	if err != nil {
		return err
	}
	return q.writeDataAtomic(q.journalPath(s.Metadata.ID), b, owner)
}
func (q *DiskQueue) clearState(id string) error {
	if err := removeIfPresent(q.journalPath(id)); err != nil {
		return err
	}
	return syncDir(q.failedDir)
}
func removeIfPresent(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
func existsChecked(path string) (bool, error) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
func (q *DiskQueue) retiredPaths(id string) (string, string, string) {
	return filepath.Join(q.failedDir, requeueRetiringPrefix+id+requeueRetiringJSON), filepath.Join(q.failedDir, requeueRetiringPrefix+id+requeueRetiringMsg), filepath.Join(q.pendingDir, requeueStagedPrefix+id+requeueStagedSuffix)
}

// restoreRetired never consumes the metadata identifying a body until the body
// rename has succeeded. Every failed step leaves enough journal information to retry.
func (q *DiskQueue) restoreRetired(id string) error {
	oldMeta, oldBody, stage := q.retiredPaths(id)
	for _, p := range [][2]string{{oldBody, filepath.Join(q.failedDir, id+".msg")}, {oldMeta, filepath.Join(q.failedDir, id+".json")}} {
		present, err := existsChecked(p[0])
		if err != nil {
			return err
		}
		if present {
			if err := os.Rename(p[0], p[1]); err != nil {
				return err
			}
		}
	}
	for _, ext := range []string{".msg", ".json"} {
		info, err := os.Stat(filepath.Join(q.failedDir, id+ext))
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("restored %s%s is not regular", id, ext)
		}
	}
	if err := syncDir(q.failedDir); err != nil {
		return err
	}
	for _, p := range []string{stage, filepath.Join(q.pendingDir, id+".msg")} {
		if err := removeIfPresent(p); err != nil {
			return err
		}
	}
	if err := syncDir(q.pendingDir); err != nil {
		return err
	}
	return q.clearState(id)
}
func (q *DiskQueue) cleanupRetired(id string) error {
	a, b, c := q.retiredPaths(id)
	for _, p := range []string{b, a, c} {
		if err := removeIfPresent(p); err != nil {
			return err
		}
	}
	if err := syncDir(q.pendingDir); err != nil {
		return err
	}
	return syncDir(q.failedDir)
}
func (q *DiskQueue) finishComplete(id string, discard bool) error {
	dirs := []string{q.pendingDir, q.processingDir}
	if discard {
		dirs = append(dirs, q.failedDir)
	}
	for _, dir := range dirs {
		for _, ext := range []string{".msg", ".json"} {
			if err := removeIfPresent(filepath.Join(dir, id+ext)); err != nil {
				return err
			}
		}
		if err := syncDir(dir); err != nil {
			return err
		}
	}
	if err := q.cleanupRetired(id); err != nil {
		return err
	}
	return q.clearState(id)
}

// recoverState requires the caller's exclusive message lease. It returns whether
// a terminal success was completed, so recovery must not requeue that message.
func (q *DiskQueue) recoverState(id string) (bool, error) {
	b, err := os.ReadFile(q.journalPath(id))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var s requeueState
	if err := json.Unmarshal(b, &s); err != nil {
		return false, err
	}
	if s.Version != 1 || s.Metadata.ID != id {
		return false, fmt.Errorf("invalid requeue journal for %s", id)
	}
	switch s.Phase {
	case "preparing", "rollback":
		return false, q.restoreRetired(id)
	case "publishing":
		body := filepath.Join(q.pendingDir, id+".msg")
		if ok, err := existsChecked(body); err != nil {
			return false, err
		} else if !ok {
			return false, fmt.Errorf("requeue %s has no staged body", id)
		}
		owner, err := foreignOwner(q.pendingDir)
		if err != nil {
			return false, err
		}
		// The durable decision contains the metadata even if the publish rename
		// consumed its staging name before the process died.
		data, err := json.MarshalIndent(s.Metadata, "", "  ")
		if err != nil {
			return false, err
		}
		if err := q.writeDataAtomic(filepath.Join(q.pendingDir, id+".json"), data, owner); err != nil {
			return false, err
		}
		s.Phase = "published"
		if err := q.writeState(s); err != nil {
			return false, err
		}
		q.pending.add(id, s.Metadata.NextRetry)
		fallthrough
	case "published":
		present := false
		failed := false
		for _, dir := range []string{q.pendingDir, q.processingDir, q.failedDir} {
			exists, err := existsChecked(filepath.Join(dir, id+".json"))
			if err != nil {
				return false, err
			}
			present = present || exists
			if dir == q.failedDir {
				failed = exists
			}
		}
		if !present {
			return false, fmt.Errorf("published requeue %s has no queue entry; retain evidence, do not redeliver", id)
		}
		if err := q.cleanupRetired(id); err != nil {
			return false, err
		}
		if failed {
			return false, q.clearState(id)
		}
		return false, nil
	case "complete":
		return true, q.finishComplete(id, s.Discard)
	default:
		return false, fmt.Errorf("unknown requeue phase %q", s.Phase)
	}
}
func (q *DiskQueue) recoverInterruptedRequeues() (int, error) {
	entries, err := os.ReadDir(q.failedDir)
	if err != nil {
		return 0, err
	}
	recovered := 0
	var errs []error
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			continue
		}
		if strings.HasPrefix(name, requeueJournalPrefix) && strings.HasSuffix(name, requeueJournalSuffix) {
			id := strings.TrimSuffix(strings.TrimPrefix(name, requeueJournalPrefix), requeueJournalSuffix)
			lease, err := q.tryLease(id)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if lease == nil {
				continue
			}
			data, readErr := os.ReadFile(q.journalPath(id))
			var before requeueState
			if readErr == nil {
				readErr = json.Unmarshal(data, &before)
			}
			if readErr == nil {
				_, err = q.recoverState(id)
			} else {
				err = readErr
			}
			lease.close()
			if err != nil {
				errs = append(errs, fmt.Errorf("recover %s: %w", id, err))
			} else if before.Phase == "publishing" || before.Phase == "preparing" || before.Phase == "rollback" {
				recovered++
			}
		}
	}
	// Old versions left no durable publication decision. Retain ambiguous evidence
	// for operator inspection; queue absence cannot prove that SMTP never succeeded.
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, requeueRetiringPrefix) || !strings.HasSuffix(name, requeueRetiringJSON) {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, requeueRetiringPrefix), requeueRetiringJSON)
		if ok, err := existsChecked(q.journalPath(id)); err != nil {
			errs = append(errs, err)
		} else if !ok {
			if old, err := existsChecked(filepath.Join(q.failedDir, name)); err != nil {
				errs = append(errs, err)
			} else if old {
				errs = append(errs, fmt.Errorf("legacy requeue %s has no publication journal; retain for manual inspection", id))
			}
		}
	}
	return recovered, errors.Join(errs...)
}

func (q *DiskQueue) finishQueueTransition() error {
	for _, dir := range []string{q.pendingDir, q.processingDir, q.failedDir} {
		if err := syncDir(dir); err != nil {
			return err
		}
	}
	return nil
}

// These sweeps recheck under the same lease used by writers. A directory snapshot
// and an old mtime alone cannot establish that an admin or delivery is dead.
func (q *DiskQueue) removeOrphan(path, id string, cutoff time.Time) (bool, error) {
	lease, err := q.tryLease(id)
	if err != nil || lease == nil {
		return false, err
	}
	defer lease.close()
	if present, err := existsChecked(q.journalPath(id)); err != nil || present {
		return false, err
	}
	oldMeta, _, _ := q.retiredPaths(id)
	if present, err := existsChecked(oldMeta); err != nil || present {
		return false, err
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.ModTime().Before(cutoff) {
		return false, nil
	}
	name := filepath.Base(path)
	var counterparts []string
	switch filepath.Ext(name) {
	case ".json":
		counterparts = []string{filepath.Join(q.pendingDir, id+".msg"), filepath.Join(q.processingDir, id+".msg")}
	case ".msg":
		counterparts = []string{filepath.Join(q.pendingDir, id+".json"), filepath.Join(q.processingDir, id+".json")}
	}
	for _, other := range counterparts {
		if present, err := existsChecked(other); err != nil || present {
			return false, err
		}
	}
	if err := removeIfPresent(path); err != nil {
		return false, err
	}
	return true, nil
}
func (q *DiskQueue) cleanupFailedEntry(name string, now time.Time, retention time.Duration) (bool, error) {
	id := strings.TrimSuffix(name, ".json")
	lease, err := q.tryLease(id)
	if err != nil || lease == nil {
		return false, err
	}
	defer lease.close()
	if present, err := existsChecked(q.journalPath(id)); err != nil || present {
		return false, err
	}
	path := filepath.Join(q.failedDir, name)
	var metadata QueuedMessage
	if err := q.readMetadata(path, &metadata); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	age := now.Sub(metadata.LastAttempt)
	if age < retention {
		return false, nil
	}
	if metadata.ID != id {
		return false, fmt.Errorf("failed message identity mismatch %s", id)
	}
	for _, p := range []string{filepath.Join(q.failedDir, id+".msg"), path} {
		if err := removeIfPresent(p); err != nil {
			return false, err
		}
	}
	if err := syncDir(q.failedDir); err != nil {
		return false, err
	}
	logger.Warn("RelayQueue: Deleted permanently failed message after retention - no copy remains", "id", id, "from", metadata.From, "to", metadata.To, "type", metadata.Type, "attempts", metadata.Attempts, "age", age.Round(time.Second), "last_error", lastError(metadata))
	return true, nil
}

// A retry/release/failure can leave destination metadata durable before its body
// rename finishes. Honor that positive decision instead of overwriting it with the
// older processing metadata. A body alone with no metadata is retained as an error.
func (q *DiskQueue) recoverProcessing(id string) (bool, error) {
	target := ""
	for _, dir := range []string{q.pendingDir, q.failedDir} {
		present, err := existsChecked(filepath.Join(dir, id+".json"))
		if err != nil {
			return false, err
		}
		if present {
			if target != "" {
				return false, fmt.Errorf("multiple destinations for processing message %s", id)
			}
			target = dir
		}
	}
	sourceMeta := filepath.Join(q.processingDir, id+".json")
	sourceBody := filepath.Join(q.processingDir, id+".msg")
	if target == "" {
		present, err := existsChecked(sourceMeta)
		if err != nil {
			return false, err
		}
		if !present {
			return false, fmt.Errorf("processing body %s has no metadata; retain for inspection", id)
		}
		target = q.pendingDir
	}
	bodyPresent, err := existsChecked(sourceBody)
	if err != nil {
		return false, err
	}
	if bodyPresent {
		if err := os.Rename(sourceBody, filepath.Join(target, id+".msg")); err != nil {
			return false, err
		}
	}
	body, err := os.Stat(filepath.Join(target, id+".msg"))
	if err != nil {
		return false, err
	}
	if !body.Mode().IsRegular() {
		return false, fmt.Errorf("recovery body %s is not regular", id)
	}
	targetMeta := filepath.Join(target, id+".json")
	if exists, err := existsChecked(targetMeta); err != nil {
		return false, err
	} else if !exists {
		if err := os.Rename(sourceMeta, targetMeta); err != nil {
			return false, err
		}
	}
	if err := syncDir(target); err != nil {
		return false, err
	}
	if err := removeIfPresent(sourceMeta); err != nil {
		return false, err
	}
	if err := syncDir(q.processingDir); err != nil {
		return false, err
	}
	if target == q.pendingDir {
		q.pending.add(id, time.Now())
	}
	return true, nil
}

// Delete serializes an explicit operator discard with writers and live delivery.
// It refuses a busy lease: removing local files cannot cancel an SMTP operation
// already in progress. A durable terminal decision also prevents crash recovery
// from resurrecting a retired copy after the administrator discarded the message.
func (q *DiskQueue) Delete(id, queue string) error {
	var dir string
	switch queue {
	case "pending":
		dir = q.pendingDir
	case "processing":
		dir = q.processingDir
	case "failed":
		dir = q.failedDir
	default:
		return fmt.Errorf("unknown relay queue %q", queue)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	lease, err := q.tryLease(id)
	if err != nil {
		return err
	}
	if lease == nil {
		return fmt.Errorf("relay message %s is busy", id)
	}
	defer lease.close()
	if _, err := q.recoverState(id); err != nil {
		return err
	}
	info, err := os.Stat(filepath.Join(dir, id+".json"))
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("relay metadata is not a regular file")
	}
	if err := q.writeState(requeueState{Phase: "complete", Discard: true, Metadata: QueuedMessage{ID: id}}); err != nil {
		return err
	}
	return q.finishComplete(id, true)
}
