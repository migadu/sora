package relayqueue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
)

const (
	// tempFilePrefix marks the scratch files written by writeDataAtomic.
	tempFilePrefix = ".tmp-"

	// orphanGracePeriod is how long a half-written message pair or a leftover temp
	// file must sit untouched before CleanupOrphans reclaims it. Every write path
	// holds q.mu, so anything older than this is crash debris rather than a write
	// still in flight.
	orphanGracePeriod = 1 * time.Hour
)

// QueuedMessage represents a message queued for relay delivery
type QueuedMessage struct {
	ID          string    `json:"id"`           // Unique message ID
	From        string    `json:"from"`         // Sender address
	To          string    `json:"to"`           // Recipient address
	Type        string    `json:"type"`         // "redirect" or "vacation"
	QueuedAt    time.Time `json:"queued_at"`    // When first queued
	Attempts    int       `json:"attempts"`     // Number of delivery attempts
	LastAttempt time.Time `json:"last_attempt"` // Last attempt timestamp
	NextRetry   time.Time `json:"next_retry"`   // When to retry next
	Errors      []string  `json:"errors"`       // Error history
}

// FailedQueueSummary describes what is sitting in the failed directory. For a Sieve
// redirect without :copy the queue file is the only copy of the message, so this is
// mail that exists nowhere else and that only a manual sora-admin relay requeue can
// still deliver.
type FailedQueueSummary struct {
	Count     int
	OldestID  string
	OldestTo  string
	OldestAge time.Duration
	LastError string
}

// DiskQueue manages a disk-based queue for relay messages
type DiskQueue struct {
	basePath      string
	pendingDir    string
	processingDir string
	failedDir     string
	maxAttempts   int
	retryBackoff  []time.Duration
	mu            sync.Mutex
	pending       *pendingIndex

	// metaRead, when set, is called before each metadata file is read from disk. It is
	// a test seam: how much of the pending backlog an operation touches, and which
	// locks it holds while doing so, are only observable from inside readMetadata.
	metaRead func()
}

// NewDiskQueue creates a new disk-based relay queue
func NewDiskQueue(basePath string, maxAttempts int, retryBackoff []time.Duration) (*DiskQueue, error) {
	if basePath == "" {
		return nil, fmt.Errorf("base path cannot be empty")
	}

	if maxAttempts <= 0 {
		maxAttempts = 10 // Default
	}

	if len(retryBackoff) == 0 {
		// Default exponential backoff
		retryBackoff = []time.Duration{
			1 * time.Minute,
			5 * time.Minute,
			15 * time.Minute,
			1 * time.Hour,
			6 * time.Hour,
			24 * time.Hour,
		}
	}

	q := &DiskQueue{
		basePath:      basePath,
		pendingDir:    filepath.Join(basePath, "pending"),
		processingDir: filepath.Join(basePath, "processing"),
		failedDir:     filepath.Join(basePath, "failed"),
		maxAttempts:   maxAttempts,
		retryBackoff:  retryBackoff,
		pending:       newPendingIndex(),
	}

	// Create directories
	for _, dir := range []string{q.pendingDir, q.processingDir, q.failedDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return q, nil
}

// RecoverOrphanedMessages moves any messages left in processing/ back to pending/
// This handles crash recovery - messages that were being processed when the server died.
func (q *DiskQueue) RecoverOrphanedMessages() (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	entries, err := os.ReadDir(q.processingDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read processing directory: %w", err)
	}

	recovered := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		ext := filepath.Ext(filename)

		// Only handle .msg and .json files
		if ext != ".msg" && ext != ".json" {
			continue
		}

		processingPath := filepath.Join(q.processingDir, filename)
		pendingPath := filepath.Join(q.pendingDir, filename)

		// Move back to pending
		if err := os.Rename(processingPath, pendingPath); err != nil {
			logger.Error("RelayQueue: Failed to recover orphaned file", "file", filename, "error", err)
			continue
		}

		// Only count .msg files to avoid double-counting (each message has .msg + .json)
		if ext == ".msg" {
			recovered++
		}
	}

	if recovered > 0 {
		// The recovered messages landed in pending/ behind the index's back.
		q.pending.invalidate()
		logger.Info("RelayQueue: Recovered orphaned messages from processing directory", "count", recovered)
	}

	return recovered, nil
}

// FailedSummary reports what is waiting in the failed directory. The oldest message
// by last attempt is the one the retention purge deletes first, so it is the one
// worth naming.
func (q *DiskQueue) FailedSummary() (FailedQueueSummary, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	entries, err := os.ReadDir(q.failedDir)
	if err != nil {
		return FailedQueueSummary{}, fmt.Errorf("failed to read failed directory: %w", err)
	}

	var summary FailedQueueSummary
	var oldest time.Time

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		summary.Count++

		var metadata QueuedMessage
		if err := q.readMetadata(filepath.Join(q.failedDir, entry.Name()), &metadata); err != nil {
			logger.Error("RelayQueue: Failed to read metadata of failed message", "file", entry.Name(), "error", err)
			continue
		}

		if !oldest.IsZero() && !metadata.LastAttempt.Before(oldest) {
			continue
		}
		oldest = metadata.LastAttempt
		summary.OldestID = metadata.ID
		summary.OldestTo = metadata.To
		summary.LastError = lastError(metadata)
	}

	if !oldest.IsZero() {
		summary.OldestAge = time.Since(oldest)
	}

	return summary, nil
}

// lastError returns the most recent delivery error recorded for a message.
func lastError(metadata QueuedMessage) string {
	if len(metadata.Errors) == 0 {
		return ""
	}
	return metadata.Errors[len(metadata.Errors)-1]
}

// CleanupOldFailedMessages removes failed messages older than the retention period.
// Returns the number of messages cleaned up.
// If retentionPeriod is 0, cleanup is disabled (messages kept forever).
func (q *DiskQueue) CleanupOldFailedMessages(retentionPeriod time.Duration) (int, error) {
	// If retention is 0, cleanup is disabled
	if retentionPeriod == 0 {
		return 0, nil
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	entries, err := os.ReadDir(q.failedDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read failed directory: %w", err)
	}

	now := time.Now()
	cleaned := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		ext := filepath.Ext(filename)

		// Only process .json metadata files (we'll delete both .json and .msg)
		if ext != ".json" {
			continue
		}

		// Read metadata to check when message was moved to failed
		metadataPath := filepath.Join(q.failedDir, filename)
		var metadata QueuedMessage
		if err := q.readMetadata(metadataPath, &metadata); err != nil {
			logger.Error("RelayQueue: Failed to read metadata during cleanup", "file", filename, "error", err)
			continue
		}

		// Calculate age based on last attempt time (when it was moved to failed)
		age := now.Sub(metadata.LastAttempt)
		if age < retentionPeriod {
			continue // Not old enough to delete
		}

		// Delete both .json and .msg files
		messageID := metadata.ID
		messagePath := filepath.Join(q.failedDir, messageID+".msg")

		// Delete message file first
		if err := os.Remove(messagePath); err != nil && !os.IsNotExist(err) {
			logger.Error("RelayQueue: Failed to delete old failed message", "id", messageID, "error", err)
			continue
		}

		// Delete metadata file
		if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
			logger.Error("RelayQueue: Failed to delete old failed metadata", "id", messageID, "error", err)
			continue
		}

		cleaned++
		// The queue file was the last copy of a message the server already answered
		// 250 for, so record what is being destroyed, not just that something was.
		logger.Warn("RelayQueue: Deleted permanently failed message after retention - no copy remains",
			"id", messageID, "from", metadata.From, "to", metadata.To, "type", metadata.Type,
			"attempts", metadata.Attempts, "age", age.Round(time.Second), "last_error", lastError(metadata))
	}

	if cleaned > 0 {
		logger.Info("RelayQueue: Cleanup completed", "cleaned", cleaned, "retention", retentionPeriod)
	}

	return cleaned, nil
}

// CleanupOrphans removes crash debris that no other path reclaims: temp files from an
// interrupted atomic write, pending bodies whose metadata was never written, and
// pending metadata whose body is missing (which AcquireNext can never deliver and
// re-reads and error-logs on every scan). Only files untouched for orphanGracePeriod
// are removed. Returns the number of files deleted.
func (q *DiskQueue) CleanupOrphans() (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	cutoff := time.Now().Add(-orphanGracePeriod)
	removed := 0

	// Leftover temp files, in every directory writeDataAtomic can target.
	for _, dir := range []string{q.pendingDir, q.processingDir, q.failedDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return removed, fmt.Errorf("failed to read directory %s: %w", dir, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), tempFilePrefix) || !modifiedBefore(entry, cutoff) {
				continue
			}
			path := filepath.Join(dir, entry.Name())
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				logger.Error("RelayQueue: Failed to remove stale temp file", "file", path, "error", err)
				continue
			}
			removed++
			logger.Info("RelayQueue: Removed stale temp file", "file", path)
		}
	}

	// Half-written message pairs in pending. Messages left in processing/ are moved
	// back here by RecoverOrphanedMessages at startup, so this covers those too.
	entries, err := os.ReadDir(q.pendingDir)
	if err != nil {
		return removed, fmt.Errorf("failed to read pending directory: %w", err)
	}

	present := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			present[entry.Name()] = true
		}
	}

	// A claim renames the metadata to processing/ and then the body, so a crash between
	// the two leaves the body here with its metadata there. That is a message being
	// delivered, not a half-write, and its body is the only copy - counting processing/
	// as "present" keeps the sweep from unlinking it. RecoverOrphanedMessages reunites
	// the pair, but it only runs at startup while this sweep runs on a ticker.
	if processingEntries, err := os.ReadDir(q.processingDir); err == nil {
		for _, entry := range processingEntries {
			if !entry.IsDir() {
				present[entry.Name()] = true
			}
		}
	} else if !os.IsNotExist(err) {
		// Without this listing the sweep cannot tell a claim in flight from a half-write,
		// so skip it entirely rather than delete on a guess.
		return removed, fmt.Errorf("failed to read processing directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filename := entry.Name()
		id := strings.TrimSuffix(filename, filepath.Ext(filename))

		var counterpart string
		switch filepath.Ext(filename) {
		case ".json":
			counterpart = id + ".msg"
		case ".msg":
			counterpart = id + ".json"
		default:
			continue
		}

		if present[counterpart] || !modifiedBefore(entry, cutoff) {
			continue
		}

		path := filepath.Join(q.pendingDir, filename)
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			logger.Error("RelayQueue: Failed to remove orphaned queue file", "file", path, "error", err)
			continue
		}
		removed++
		logger.Warn("RelayQueue: Removed orphaned queue file", "file", path, "id", id)
	}

	if removed > 0 {
		logger.Info("RelayQueue: Orphan cleanup completed", "removed", removed)
	}

	return removed, nil
}

// Enqueue adds a new message to the relay queue
func (q *DiskQueue) Enqueue(from, to, messageType string, messageBytes []byte) error {
	start := time.Now()
	q.mu.Lock()
	defer q.mu.Unlock()

	// Generate unique ID
	id := uuid.New().String()

	// Create metadata
	metadata := QueuedMessage{
		ID:          id,
		From:        from,
		To:          to,
		Type:        messageType,
		QueuedAt:    time.Now(),
		Attempts:    0,
		LastAttempt: time.Time{},
		NextRetry:   time.Now(), // Ready for immediate processing
		Errors:      []string{},
	}

	// Write the message body first: AcquireNext keys off the .json file, so metadata
	// becoming visible must imply the body is already on disk. The reverse order
	// leaves an undeliverable .json behind if the process dies between the two writes.
	messagePath := filepath.Join(q.pendingDir, id+".msg")
	if err := q.writeDataAtomic(messagePath, messageBytes); err != nil {
		metrics.RelayQueueOperations.WithLabelValues("enqueue", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("enqueue").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to write message: %w", err)
	}

	// Write metadata atomically
	metadataPath := filepath.Join(q.pendingDir, id+".json")
	if err := q.writeFileAtomic(metadataPath, metadata); err != nil {
		// Clean up the body if metadata write fails
		os.Remove(messagePath)
		metrics.RelayQueueOperations.WithLabelValues("enqueue", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("enqueue").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	q.pending.add(id, metadata.NextRetry)

	metrics.RelayQueueOperations.WithLabelValues("enqueue", "success").Inc()
	metrics.RelayQueueOperationDuration.WithLabelValues("enqueue").Observe(time.Since(start).Seconds())
	logger.Info("RelayQueue: Enqueued message", "type", messageType, "id", id, "from", from, "to", to)
	return nil
}

// AcquireNext finds the next message ready for processing and moves it to processing state.
// Candidates come from the in-memory pending index rather than a fresh directory scan,
// so the cost of an acquire does not grow with the size of the backlog.
func (q *DiskQueue) AcquireNext() (*QueuedMessage, []byte, error) {
	start := time.Now()

	if err := q.syncPendingIndex(start); err != nil {
		metrics.RelayQueueOperations.WithLabelValues("acquire", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("acquire").Observe(time.Since(start).Seconds())
		return nil, nil, err
	}

	// Take candidates until one can actually be claimed: an index entry whose files
	// have gone is skipped, exactly as the old scan skipped unreadable entries.
	for {
		messageID, ok := q.pending.takeDue(time.Now())
		if !ok {
			// No messages ready - this is normal, not an error
			metrics.RelayQueueOperationDuration.WithLabelValues("acquire").Observe(time.Since(start).Seconds())
			return nil, nil, nil
		}

		metadata, messageBytes, ok := q.claimPending(messageID)
		if !ok {
			continue
		}

		metrics.RelayQueueOperations.WithLabelValues("acquire", "success").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("acquire").Observe(time.Since(start).Seconds())
		return metadata, messageBytes, nil
	}
}

// syncPendingIndex rebuilds the index from the pending directory when it has gone
// stale, which also picks up messages placed there by another process such as
// `sora-admin relay requeue`. The scan holds no lock: it is the one step whose cost is
// the backlog, and nothing - least of all Enqueue - may wait behind it.
func (q *DiskQueue) syncPendingIndex(now time.Time) error {
	if !q.pending.stale(now) {
		return nil
	}

	entries, err := os.ReadDir(q.pendingDir)
	if err != nil {
		return fmt.Errorf("failed to read pending directory: %w", err)
	}

	onDisk := make(map[string]time.Time, len(entries)/2)
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		var metadata QueuedMessage
		if err := q.readMetadata(filepath.Join(q.pendingDir, entry.Name()), &metadata); err != nil {
			logger.Error("RelayQueue: Failed to read metadata", "entry", entry.Name(), "error", err)
			continue
		}
		onDisk[strings.TrimSuffix(entry.Name(), ".json")] = metadata.NextRetry
	}

	q.pending.merge(onDisk, now)
	return nil
}

// claimPending moves one message from pending to processing. It reports false when the
// message cannot be claimed - gone, unreadable, or not actually due - in which case the
// caller moves on to the next candidate.
func (q *DiskQueue) claimPending(messageID string) (*QueuedMessage, []byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	metadataPath := filepath.Join(q.pendingDir, messageID+".json")
	messagePath := filepath.Join(q.pendingDir, messageID+".msg")

	var metadata QueuedMessage
	if err := q.readMetadata(metadataPath, &metadata); err != nil {
		// A message that is simply no longer there was removed out of band; the old
		// directory scan would not have listed it either, so it is not worth a log line.
		if !os.IsNotExist(err) {
			logger.Error("RelayQueue: Failed to read metadata", "message_id", messageID, "error", err)
		}
		return nil, nil, false
	}

	// The directory is the source of truth: if it disagrees with the index about the
	// retry time, put the message back with what disk says.
	if time.Now().Before(metadata.NextRetry) {
		q.pending.add(messageID, metadata.NextRetry)
		return nil, nil, false
	}

	messageBytes, err := os.ReadFile(messagePath)
	if err != nil {
		logger.Error("RelayQueue: Failed to read message", "message_id", messageID, "error", err)
		return nil, nil, false
	}

	// Move to processing directory atomically
	processingMetadataPath := filepath.Join(q.processingDir, messageID+".json")
	processingMessagePath := filepath.Join(q.processingDir, messageID+".msg")

	// Move metadata
	if err := os.Rename(metadataPath, processingMetadataPath); err != nil {
		logger.Error("RelayQueue: Failed to move metadata to processing", "error", err)
		return nil, nil, false
	}

	// Move message
	if err := os.Rename(messagePath, processingMessagePath); err != nil {
		// Try to move metadata back. The message is deliberately not put back into the
		// index: it is still due, so re-adding it would spin this loop on a failure
		// that is not going away. The next resync picks it up.
		os.Rename(processingMetadataPath, metadataPath)
		logger.Error("RelayQueue: Failed to move message to processing", "error", err)
		return nil, nil, false
	}

	return &metadata, messageBytes, true
}

// MarkSuccess removes the message from the queue after successful delivery
func (q *DiskQueue) MarkSuccess(messageID string) error {
	start := time.Now()
	q.mu.Lock()
	defer q.mu.Unlock()

	metadataPath := filepath.Join(q.processingDir, messageID+".json")
	messagePath := filepath.Join(q.processingDir, messageID+".msg")

	// Remove both files
	if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
		metrics.RelayQueueOperations.WithLabelValues("mark_success", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("mark_success").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to remove metadata: %w", err)
	}
	if err := os.Remove(messagePath); err != nil && !os.IsNotExist(err) {
		metrics.RelayQueueOperations.WithLabelValues("mark_success", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("mark_success").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to remove message: %w", err)
	}

	metrics.RelayQueueOperations.WithLabelValues("mark_success", "success").Inc()
	metrics.RelayQueueOperationDuration.WithLabelValues("mark_success").Observe(time.Since(start).Seconds())
	logger.Info("RelayQueue: Successfully delivered message", "id", messageID)
	return nil
}

// MarkPermanentFailure immediately moves a message to failed directory without retry.
// This is used for permanent SMTP errors (5xx codes) that should not be retried.
func (q *DiskQueue) MarkPermanentFailure(messageID string, errorMsg string) error {
	start := time.Now()
	q.mu.Lock()
	defer q.mu.Unlock()

	metadataPath := filepath.Join(q.processingDir, messageID+".json")
	messagePath := filepath.Join(q.processingDir, messageID+".msg")

	// Read current metadata
	var metadata QueuedMessage
	if err := q.readMetadata(metadataPath, &metadata); err != nil {
		metrics.RelayQueueOperations.WithLabelValues("mark_permanent_failure", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("mark_permanent_failure").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	// Update metadata
	metadata.Attempts++
	metadata.LastAttempt = time.Now()
	metadata.Errors = append(metadata.Errors, fmt.Sprintf("[%s] PERMANENT: %s", time.Now().Format(time.RFC3339), errorMsg))

	logger.Error("RelayQueue: Permanent failure (5xx or similar), moving to failed", "id", messageID, "error", errorMsg)

	// Move to failed directory
	failedMetadataPath := filepath.Join(q.failedDir, messageID+".json")
	failedMessagePath := filepath.Join(q.failedDir, messageID+".msg")

	if err := q.writeFileAtomic(failedMetadataPath, metadata); err != nil {
		metrics.RelayQueueOperations.WithLabelValues("mark_permanent_failure", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("mark_permanent_failure").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to write failed metadata: %w", err)
	}

	if err := os.Rename(messagePath, failedMessagePath); err != nil {
		metrics.RelayQueueOperations.WithLabelValues("mark_permanent_failure", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("mark_permanent_failure").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to move message to failed: %w", err)
	}

	// Remove from processing
	os.Remove(metadataPath)
	metrics.RelayQueueOperations.WithLabelValues("mark_permanent_failure", "success").Inc()
	metrics.RelayQueueOperationDuration.WithLabelValues("mark_permanent_failure").Observe(time.Since(start).Seconds())
	return nil
}

// MarkFailure updates the message after a failed delivery attempt (for temporary failures).
// This is used for temporary SMTP errors (4xx codes) and network errors.
func (q *DiskQueue) MarkFailure(messageID string, errorMsg string) error {
	start := time.Now()
	q.mu.Lock()
	defer q.mu.Unlock()

	metadataPath := filepath.Join(q.processingDir, messageID+".json")
	messagePath := filepath.Join(q.processingDir, messageID+".msg")

	// Read current metadata
	var metadata QueuedMessage
	if err := q.readMetadata(metadataPath, &metadata); err != nil {
		metrics.RelayQueueOperations.WithLabelValues("mark_failure", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("mark_failure").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	// Update metadata
	metadata.Attempts++
	metadata.LastAttempt = time.Now()
	metadata.Errors = append(metadata.Errors, fmt.Sprintf("[%s] %s", time.Now().Format(time.RFC3339), errorMsg))

	// Check if max attempts exceeded
	if metadata.Attempts >= q.maxAttempts {
		logger.Error("RelayQueue: Message exceeded max attempts, moving to failed", "id", messageID, "max_attempts", q.maxAttempts)

		// Move to failed directory
		failedMetadataPath := filepath.Join(q.failedDir, messageID+".json")
		failedMessagePath := filepath.Join(q.failedDir, messageID+".msg")

		if err := q.writeFileAtomic(failedMetadataPath, metadata); err != nil {
			metrics.RelayQueueOperations.WithLabelValues("mark_failure", "error").Inc()
			metrics.RelayQueueOperationDuration.WithLabelValues("mark_failure").Observe(time.Since(start).Seconds())
			return fmt.Errorf("failed to write failed metadata: %w", err)
		}

		if err := os.Rename(messagePath, failedMessagePath); err != nil {
			metrics.RelayQueueOperations.WithLabelValues("mark_failure", "error").Inc()
			metrics.RelayQueueOperationDuration.WithLabelValues("mark_failure").Observe(time.Since(start).Seconds())
			return fmt.Errorf("failed to move message to failed: %w", err)
		}

		// Remove from processing
		os.Remove(metadataPath)
		metrics.RelayQueueOperations.WithLabelValues("mark_failure", "success").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("mark_failure").Observe(time.Since(start).Seconds())
		return nil
	}

	// Calculate next retry time with exponential backoff
	backoffIndex := metadata.Attempts - 1
	if backoffIndex >= len(q.retryBackoff) {
		backoffIndex = len(q.retryBackoff) - 1
	}
	metadata.NextRetry = time.Now().Add(q.retryBackoff[backoffIndex])

	logger.Info("RelayQueue: Message delivery failed", "id", messageID,
		"attempt", metadata.Attempts, "max_attempts", q.maxAttempts,
		"retry_at", metadata.NextRetry.Format(time.RFC3339), "error", errorMsg)

	// Move back to pending directory for retry
	pendingMetadataPath := filepath.Join(q.pendingDir, messageID+".json")
	pendingMessagePath := filepath.Join(q.pendingDir, messageID+".msg")

	if err := q.writeFileAtomic(pendingMetadataPath, metadata); err != nil {
		metrics.RelayQueueOperations.WithLabelValues("mark_failure", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("mark_failure").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to write pending metadata: %w", err)
	}

	if err := os.Rename(messagePath, pendingMessagePath); err != nil {
		// Try to clean up metadata
		os.Remove(pendingMetadataPath)
		metrics.RelayQueueOperations.WithLabelValues("mark_failure", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("mark_failure").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to move message to pending: %w", err)
	}

	// Remove from processing
	os.Remove(metadataPath)
	q.pending.add(messageID, metadata.NextRetry)
	metrics.RelayQueueOperations.WithLabelValues("mark_failure", "success").Inc()
	metrics.RelayQueueOperationDuration.WithLabelValues("mark_failure").Observe(time.Since(start).Seconds())
	return nil
}

// Release moves a message from processing back to pending without incrementing attempts.
// This is useful when a message cannot be processed due to transient conditions like
// circuit breaker being open, and should be retried on the next worker cycle without penalty.
func (q *DiskQueue) Release(messageID string) error {
	start := time.Now()
	q.mu.Lock()
	defer q.mu.Unlock()

	metadataPath := filepath.Join(q.processingDir, messageID+".json")
	messagePath := filepath.Join(q.processingDir, messageID+".msg")

	// Read current metadata
	var metadata QueuedMessage
	if err := q.readMetadata(metadataPath, &metadata); err != nil {
		metrics.RelayQueueOperations.WithLabelValues("release", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("release").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to read metadata: %w", err)
	}

	// Don't increment attempts or add error - just move back to pending
	// Set NextRetry to immediate - the worker interval will naturally rate-limit retries
	metadata.NextRetry = time.Now()

	// Move back to pending directory
	pendingMetadataPath := filepath.Join(q.pendingDir, messageID+".json")
	pendingMessagePath := filepath.Join(q.pendingDir, messageID+".msg")

	if err := q.writeFileAtomic(pendingMetadataPath, metadata); err != nil {
		metrics.RelayQueueOperations.WithLabelValues("release", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("release").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to write pending metadata: %w", err)
	}

	if err := os.Rename(messagePath, pendingMessagePath); err != nil {
		// Try to clean up metadata
		os.Remove(pendingMetadataPath)
		metrics.RelayQueueOperations.WithLabelValues("release", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("release").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to move message to pending: %w", err)
	}

	// Remove from processing
	os.Remove(metadataPath)
	q.pending.add(messageID, metadata.NextRetry)
	metrics.RelayQueueOperations.WithLabelValues("release", "success").Inc()
	metrics.RelayQueueOperationDuration.WithLabelValues("release").Observe(time.Since(start).Seconds())
	return nil
}

// GetStats returns queue statistics. It counts the directories without taking q.mu:
// these are gauges refreshed on every worker cycle, and a count that is one message off
// because a rename happened mid-listing is not worth making inbound mail wait for a
// walk of the whole backlog.
func (q *DiskQueue) GetStats() (pending, processing, failed int, err error) {
	pending, err = q.countDir(q.pendingDir, ".json")
	if err != nil {
		return 0, 0, 0, err
	}

	processing, err = q.countDir(q.processingDir, ".json")
	if err != nil {
		return 0, 0, 0, err
	}

	failed, err = q.countDir(q.failedDir, ".json")
	if err != nil {
		return 0, 0, 0, err
	}

	return pending, processing, failed, nil
}

// writeFileAtomic writes data to a file atomically using temp file + rename
func (q *DiskQueue) writeFileAtomic(path string, data any) error {
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	return q.writeDataAtomic(path, jsonBytes)
}

// writeDataAtomic writes raw bytes to a file atomically using temp file + rename.
// Both the data and the directory entry are fsynced: for a Sieve redirect without
// :copy, LMTP answers 250 and skips local delivery, so these files are the only copy
// of the message. Without the fsyncs a power loss can drop the rename entirely, or
// land the new name over an unwritten (zero-length) body that would then be relayed.
// Reporting a sync failure is safe: LMTP falls back to local delivery when Enqueue
// fails, and the other callers leave the message in processing/ for crash recovery.
func (q *DiskQueue) writeDataAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, tempFilePrefix)
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	// Write, flush to stable storage, and close
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}

	// Fsync the parent directory so the rename itself is durable
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("failed to fsync directory %s: %w", dir, err)
	}

	return nil
}

// syncDir fsyncs a directory to ensure renamed and newly created entries are durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// readMetadata reads and unmarshals metadata from a JSON file
func (q *DiskQueue) readMetadata(path string, metadata *QueuedMessage) error {
	if q.metaRead != nil {
		q.metaRead()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, metadata)
}

// modifiedBefore reports whether a directory entry was last modified before cutoff.
// An entry whose metadata cannot be read is treated as too recent to touch.
func modifiedBefore(entry os.DirEntry, cutoff time.Time) bool {
	info, err := entry.Info()
	if err != nil {
		return false
	}
	return info.ModTime().Before(cutoff)
}

// countDir counts files with given extension in a directory
func (q *DiskQueue) countDir(dir string, ext string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ext {
			count++
		}
	}
	return count, nil
}
