package relayqueue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
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

// DiskQueue manages a disk-based queue for relay messages
type DiskQueue struct {
	basePath      string
	pendingDir    string
	processingDir string
	failedDir     string
	maxAttempts   int
	retryBackoff  []time.Duration
	mu            sync.Mutex
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
	}

	// Create directories
	for _, dir := range []string{q.pendingDir, q.processingDir, q.failedDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return q, nil
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

	// Write metadata atomically
	metadataPath := filepath.Join(q.pendingDir, id+".json")
	if err := q.writeFileAtomic(metadataPath, metadata); err != nil {
		metrics.RelayQueueOperations.WithLabelValues("enqueue", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("enqueue").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to write metadata: %w", err)
	}

	// Write message body atomically
	messagePath := filepath.Join(q.pendingDir, id+".msg")
	if err := q.writeDataAtomic(messagePath, messageBytes); err != nil {
		// Clean up metadata if message write fails
		os.Remove(metadataPath)
		metrics.RelayQueueOperations.WithLabelValues("enqueue", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("enqueue").Observe(time.Since(start).Seconds())
		return fmt.Errorf("failed to write message: %w", err)
	}

	metrics.RelayQueueOperations.WithLabelValues("enqueue", "success").Inc()
	metrics.RelayQueueOperationDuration.WithLabelValues("enqueue").Observe(time.Since(start).Seconds())
	logger.Info("RelayQueue: Enqueued message", "type", messageType, "id", id, "from", from, "to", to)
	return nil
}

// AcquireNext finds the next message ready for processing and moves it to processing state
func (q *DiskQueue) AcquireNext() (*QueuedMessage, []byte, error) {
	start := time.Now()
	q.mu.Lock()
	defer q.mu.Unlock()

	// List pending messages
	entries, err := os.ReadDir(q.pendingDir)
	if err != nil {
		metrics.RelayQueueOperations.WithLabelValues("acquire", "error").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("acquire").Observe(time.Since(start).Seconds())
		return nil, nil, fmt.Errorf("failed to read pending directory: %w", err)
	}

	now := time.Now()

	// Find first message ready for retry
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		// Read metadata
		metadataPath := filepath.Join(q.pendingDir, entry.Name())
		var metadata QueuedMessage
		if err := q.readMetadata(metadataPath, &metadata); err != nil {
			logger.Error("RelayQueue: Failed to read metadata", "entry", entry.Name(), "error", err)
			continue
		}

		// Check if ready for retry
		if now.Before(metadata.NextRetry) {
			continue
		}

		// Read message body
		messageID := metadata.ID
		messagePath := filepath.Join(q.pendingDir, messageID+".msg")
		messageBytes, err := os.ReadFile(messagePath)
		if err != nil {
			logger.Error("RelayQueue: Failed to read message", "message_id", messageID, "error", err)
			continue
		}

		// Move to processing directory atomically
		processingMetadataPath := filepath.Join(q.processingDir, messageID+".json")
		processingMessagePath := filepath.Join(q.processingDir, messageID+".msg")

		// Move metadata
		if err := os.Rename(metadataPath, processingMetadataPath); err != nil {
			logger.Error("RelayQueue: Failed to move metadata to processing", "error", err)
			continue
		}

		// Move message
		if err := os.Rename(messagePath, processingMessagePath); err != nil {
			// Try to move metadata back
			os.Rename(processingMetadataPath, metadataPath)
			logger.Error("RelayQueue: Failed to move message to processing", "error", err)
			continue
		}

		metrics.RelayQueueOperations.WithLabelValues("acquire", "success").Inc()
		metrics.RelayQueueOperationDuration.WithLabelValues("acquire").Observe(time.Since(start).Seconds())
		return &metadata, messageBytes, nil
	}

	// No messages ready - this is normal, not an error
	metrics.RelayQueueOperationDuration.WithLabelValues("acquire").Observe(time.Since(start).Seconds())
	return nil, nil, nil
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

// MarkFailure updates the message after a failed delivery attempt
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
	metrics.RelayQueueOperations.WithLabelValues("mark_failure", "success").Inc()
	metrics.RelayQueueOperationDuration.WithLabelValues("mark_failure").Observe(time.Since(start).Seconds())
	return nil
}

// GetStats returns queue statistics
func (q *DiskQueue) GetStats() (pending, processing, failed int, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()

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

// writeDataAtomic writes raw bytes to a file atomically using temp file + rename
func (q *DiskQueue) writeDataAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".tmp-")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()

	// Write and close
	if _, err := tmpFile.Write(data); err != nil {
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

	return nil
}

// readMetadata reads and unmarshals metadata from a JSON file
func (q *DiskQueue) readMetadata(path string, metadata *QueuedMessage) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, metadata)
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
