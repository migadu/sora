package relayqueue

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNewDiskQueue tests queue creation
func TestNewDiskQueue(t *testing.T) {
	tests := []struct {
		name            string
		basePath        string
		maxAttempts     int
		retryBackoff    []time.Duration
		expectError     bool
		expectedMax     int
		expectedBackoff int
	}{
		{
			name:            "Valid queue with defaults",
			basePath:        t.TempDir(),
			maxAttempts:     10,
			retryBackoff:    nil,
			expectError:     false,
			expectedMax:     10,
			expectedBackoff: 6,
		},
		{
			name:            "Valid queue with custom backoff",
			basePath:        t.TempDir(),
			maxAttempts:     5,
			retryBackoff:    []time.Duration{1 * time.Minute, 5 * time.Minute},
			expectError:     false,
			expectedMax:     5,
			expectedBackoff: 2,
		},
		{
			name:         "Empty base path",
			basePath:     "",
			maxAttempts:  10,
			retryBackoff: nil,
			expectError:  true,
		},
		{
			name:         "Zero max attempts uses default",
			basePath:     t.TempDir(),
			maxAttempts:  0,
			retryBackoff: nil,
			expectError:  false,
			expectedMax:  10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queue, err := NewDiskQueue(tt.basePath, tt.maxAttempts, tt.retryBackoff)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if queue == nil {
				t.Fatal("Expected non-nil queue")
			}

			// Verify directories were created
			if _, err := os.Stat(queue.pendingDir); os.IsNotExist(err) {
				t.Errorf("Pending directory not created: %s", queue.pendingDir)
			}
			if _, err := os.Stat(queue.processingDir); os.IsNotExist(err) {
				t.Errorf("Processing directory not created: %s", queue.processingDir)
			}
			if _, err := os.Stat(queue.failedDir); os.IsNotExist(err) {
				t.Errorf("Failed directory not created: %s", queue.failedDir)
			}

			// Verify configuration
			if queue.maxAttempts != tt.expectedMax {
				t.Errorf("Expected maxAttempts %d, got %d", tt.expectedMax, queue.maxAttempts)
			}

			if tt.expectedBackoff > 0 && len(queue.retryBackoff) != tt.expectedBackoff {
				t.Errorf("Expected %d backoff intervals, got %d", tt.expectedBackoff, len(queue.retryBackoff))
			}
		})
	}
}

// TestEnqueue tests message enqueueing
func TestEnqueue(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	tests := []struct {
		name        string
		from        string
		to          string
		messageType string
		message     []byte
	}{
		{
			name:        "Redirect message",
			from:        "sender@example.com",
			to:          "recipient@example.com",
			messageType: "redirect",
			message:     []byte("Subject: Test\r\n\r\nTest message"),
		},
		{
			name:        "Vacation message",
			from:        "user@example.com",
			to:          "sender@example.com",
			messageType: "vacation",
			message:     []byte("Subject: Out of Office\r\n\r\nI am away"),
		},
		{
			name:        "Large message",
			from:        "sender@example.com",
			to:          "recipient@example.com",
			messageType: "redirect",
			message:     make([]byte, 1024*1024), // 1MB
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := queue.Enqueue(tt.from, tt.to, tt.messageType, tt.message)
			if err != nil {
				t.Fatalf("Enqueue failed: %v", err)
			}

			// Verify files were created
			entries, err := os.ReadDir(queue.pendingDir)
			if err != nil {
				t.Fatalf("Failed to read pending directory: %v", err)
			}

			// Should have at least the files we enqueued
			if len(entries) < 2 {
				t.Errorf("Expected at least 2 files (metadata + message), got %d", len(entries))
			}
		})
	}

	// Verify queue stats
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if pending != len(tests) {
		t.Errorf("Expected %d pending messages, got %d", len(tests), pending)
	}
	if processing != 0 {
		t.Errorf("Expected 0 processing messages, got %d", processing)
	}
	if failed != 0 {
		t.Errorf("Expected 0 failed messages, got %d", failed)
	}
}

// TestAcquireNext tests acquiring messages for processing
func TestAcquireNext(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Enqueue a message
	from := "sender@example.com"
	to := "recipient@example.com"
	messageType := "redirect"
	message := []byte("Test message")

	err = queue.Enqueue(from, to, messageType, message)
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Acquire the message
	msg, msgBytes, err := queue.AcquireNext()
	if err != nil {
		t.Fatalf("AcquireNext failed: %v", err)
	}

	if msg == nil {
		t.Fatal("Expected message, got nil")
	}

	// Verify message fields
	if msg.From != from {
		t.Errorf("Expected from %s, got %s", from, msg.From)
	}
	if msg.To != to {
		t.Errorf("Expected to %s, got %s", to, msg.To)
	}
	if msg.Type != messageType {
		t.Errorf("Expected type %s, got %s", messageType, msg.Type)
	}
	if msg.Attempts != 0 {
		t.Errorf("Expected 0 attempts, got %d", msg.Attempts)
	}
	if string(msgBytes) != string(message) {
		t.Errorf("Message bytes don't match")
	}

	// Verify message moved to processing
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if pending != 0 {
		t.Errorf("Expected 0 pending, got %d", pending)
	}
	if processing != 1 {
		t.Errorf("Expected 1 processing, got %d", processing)
	}
	if failed != 0 {
		t.Errorf("Expected 0 failed, got %d", failed)
	}

	// Try to acquire again - should get nothing
	msg2, _, err := queue.AcquireNext()
	if err != nil {
		t.Fatalf("Second AcquireNext failed: %v", err)
	}
	if msg2 != nil {
		t.Error("Expected nil (no more messages), got message")
	}
}

// TestAcquireNextWithRetryDelay tests that messages aren't acquired before their retry time
func TestAcquireNextWithRetryDelay(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, []time.Duration{100 * time.Millisecond})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Enqueue a message
	err = queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test"))
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Acquire and fail it
	msg, msgBytes, err := queue.AcquireNext()
	if err != nil || msg == nil {
		t.Fatalf("Initial acquire failed: %v", err)
	}

	err = queue.MarkFailure(msg.ID, "Test failure")
	if err != nil {
		t.Fatalf("MarkFailure failed: %v", err)
	}

	// Try to acquire immediately - should get nothing (still in retry delay)
	msg2, _, err := queue.AcquireNext()
	if err != nil {
		t.Fatalf("AcquireNext failed: %v", err)
	}
	if msg2 != nil {
		t.Error("Expected nil (message in retry delay), got message")
	}

	// Wait for retry delay
	time.Sleep(150 * time.Millisecond)

	// Now should be able to acquire
	msg3, msgBytes3, err := queue.AcquireNext()
	if err != nil {
		t.Fatalf("AcquireNext after delay failed: %v", err)
	}
	if msg3 == nil {
		t.Fatal("Expected message after retry delay, got nil")
	}
	if msg3.ID != msg.ID {
		t.Errorf("Expected same message ID %s, got %s", msg.ID, msg3.ID)
	}
	if string(msgBytes3) != string(msgBytes) {
		t.Error("Message bytes don't match after retry")
	}
	if msg3.Attempts != 1 {
		t.Errorf("Expected 1 attempt, got %d", msg3.Attempts)
	}
}

// TestMarkSuccess tests successful message removal
func TestMarkSuccess(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Enqueue and acquire
	err = queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test"))
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	msg, _, err := queue.AcquireNext()
	if err != nil || msg == nil {
		t.Fatalf("AcquireNext failed: %v", err)
	}

	// Mark as success
	err = queue.MarkSuccess(msg.ID)
	if err != nil {
		t.Fatalf("MarkSuccess failed: %v", err)
	}

	// Verify all counts are zero
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if pending != 0 || processing != 0 || failed != 0 {
		t.Errorf("Expected all zero, got pending=%d processing=%d failed=%d", pending, processing, failed)
	}

	// Verify files are deleted
	entries, err := os.ReadDir(queue.processingDir)
	if err != nil {
		t.Fatalf("Failed to read processing directory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Expected 0 files in processing, got %d", len(entries))
	}
}

// TestMarkFailureWithRetry tests failure handling with retry
func TestMarkFailureWithRetry(t *testing.T) {
	backoff := []time.Duration{1 * time.Minute, 5 * time.Minute}
	queue, err := NewDiskQueue(t.TempDir(), 10, backoff)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Enqueue and acquire
	err = queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test"))
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	msg, _, err := queue.AcquireNext()
	if err != nil || msg == nil {
		t.Fatalf("AcquireNext failed: %v", err)
	}

	// Mark as failure
	err = queue.MarkFailure(msg.ID, "Test error")
	if err != nil {
		t.Fatalf("MarkFailure failed: %v", err)
	}

	// Verify message moved back to pending
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if pending != 1 {
		t.Errorf("Expected 1 pending (for retry), got %d", pending)
	}
	if processing != 0 {
		t.Errorf("Expected 0 processing, got %d", processing)
	}
	if failed != 0 {
		t.Errorf("Expected 0 failed, got %d", failed)
	}

	// Read the metadata to verify it was updated
	entries, err := os.ReadDir(queue.pendingDir)
	if err != nil {
		t.Fatalf("Failed to read pending directory: %v", err)
	}

	var metadata QueuedMessage
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			path := filepath.Join(queue.pendingDir, entry.Name())
			if err := queue.readMetadata(path, &metadata); err == nil {
				break
			}
		}
	}

	if metadata.Attempts != 1 {
		t.Errorf("Expected 1 attempt, got %d", metadata.Attempts)
	}
	if len(metadata.Errors) != 1 {
		t.Errorf("Expected 1 error, got %d", len(metadata.Errors))
	}
	if metadata.LastAttempt.IsZero() {
		t.Error("Expected LastAttempt to be set")
	}
	if metadata.NextRetry.IsZero() {
		t.Error("Expected NextRetry to be set")
	}
}

// TestMarkFailureMaxAttempts tests that messages move to failed after max attempts
func TestMarkFailureMaxAttempts(t *testing.T) {
	maxAttempts := 3
	queue, err := NewDiskQueue(t.TempDir(), maxAttempts, []time.Duration{1 * time.Millisecond})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Enqueue a message
	err = queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test"))
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Fail it maxAttempts times
	for i := 0; i < maxAttempts; i++ {
		// Wait for retry delay
		if i > 0 {
			time.Sleep(5 * time.Millisecond)
		}

		msg, _, err := queue.AcquireNext()
		if err != nil || msg == nil {
			t.Fatalf("AcquireNext attempt %d failed: %v", i+1, err)
		}

		err = queue.MarkFailure(msg.ID, "Test error")
		if err != nil {
			t.Fatalf("MarkFailure attempt %d failed: %v", i+1, err)
		}
	}

	// Verify message is in failed directory
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if pending != 0 {
		t.Errorf("Expected 0 pending, got %d", pending)
	}
	if processing != 0 {
		t.Errorf("Expected 0 processing, got %d", processing)
	}
	if failed != 1 {
		t.Errorf("Expected 1 failed, got %d", failed)
	}

	// Verify metadata shows correct attempts
	entries, err := os.ReadDir(queue.failedDir)
	if err != nil {
		t.Fatalf("Failed to read failed directory: %v", err)
	}

	var metadata QueuedMessage
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			path := filepath.Join(queue.failedDir, entry.Name())
			if err := queue.readMetadata(path, &metadata); err == nil {
				break
			}
		}
	}

	if metadata.Attempts != maxAttempts {
		t.Errorf("Expected %d attempts, got %d", maxAttempts, metadata.Attempts)
	}
	if len(metadata.Errors) != maxAttempts {
		t.Errorf("Expected %d errors, got %d", maxAttempts, len(metadata.Errors))
	}
}

// TestConcurrentEnqueue tests concurrent enqueuing
func TestConcurrentEnqueue(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	numGoroutines := 10
	messagesPerGoroutine := 10
	done := make(chan bool)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < messagesPerGoroutine; j++ {
				err := queue.Enqueue(
					"sender@example.com",
					"recipient@example.com",
					"redirect",
					[]byte("Test message"),
				)
				if err != nil {
					t.Errorf("Concurrent enqueue failed: %v", err)
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all messages were enqueued
	pending, _, _, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	expected := numGoroutines * messagesPerGoroutine
	if pending != expected {
		t.Errorf("Expected %d pending messages, got %d", expected, pending)
	}
}

// TestGetStats tests statistics retrieval
func TestGetStats(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Initially empty
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if pending != 0 || processing != 0 || failed != 0 {
		t.Errorf("Expected all zero initially, got pending=%d processing=%d failed=%d", pending, processing, failed)
	}

	// Enqueue some messages
	for i := 0; i < 3; i++ {
		queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test"))
	}

	pending, processing, failed, err = queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if pending != 3 || processing != 0 || failed != 0 {
		t.Errorf("Expected pending=3 processing=0 failed=0, got pending=%d processing=%d failed=%d", pending, processing, failed)
	}

	// Acquire one
	msg, _, _ := queue.AcquireNext()

	pending, processing, failed, err = queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if pending != 2 || processing != 1 || failed != 0 {
		t.Errorf("Expected pending=2 processing=1 failed=0, got pending=%d processing=%d failed=%d", pending, processing, failed)
	}

	// Fail it with max attempts
	queue.maxAttempts = 1
	queue.MarkFailure(msg.ID, "Test error")

	pending, processing, failed, err = queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if pending != 2 || processing != 0 || failed != 1 {
		t.Errorf("Expected pending=2 processing=0 failed=1, got pending=%d processing=%d failed=%d", pending, processing, failed)
	}
}

// TestAtomicWrites tests that writes are atomic
func TestAtomicWrites(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Enqueue a message
	err = queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test"))
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Verify no .tmp files were left behind
	checkForTempFiles := func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("Failed to read directory %s: %v", dir, err)
		}
		for _, entry := range entries {
			if filepath.Ext(entry.Name()) == ".tmp-" || entry.Name()[:4] == ".tmp" {
				t.Errorf("Found temporary file in %s: %s", dir, entry.Name())
			}
		}
	}

	checkForTempFiles(queue.pendingDir)
	checkForTempFiles(queue.processingDir)
	checkForTempFiles(queue.failedDir)
}

// BenchmarkEnqueue benchmarks message enqueueing
func BenchmarkEnqueue(b *testing.B) {
	queue, err := NewDiskQueue(b.TempDir(), 10, nil)
	if err != nil {
		b.Fatalf("Failed to create queue: %v", err)
	}

	message := []byte("Subject: Test\r\n\r\nTest message body")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", message)
	}
}

// BenchmarkAcquireNext benchmarks message acquisition
func BenchmarkAcquireNext(b *testing.B) {
	queue, err := NewDiskQueue(b.TempDir(), 10, nil)
	if err != nil {
		b.Fatalf("Failed to create queue: %v", err)
	}

	// Pre-populate queue
	message := []byte("Subject: Test\r\n\r\nTest message body")
	for i := 0; i < 1000; i++ {
		queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", message)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		msg, _, _ := queue.AcquireNext()
		if msg != nil {
			queue.MarkSuccess(msg.ID)
		}
	}
}

// TestMarkPermanentFailure tests that permanent failures are immediately moved to failed directory
func TestMarkPermanentFailure(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Enqueue a message
	err = queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test message"))
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Acquire the message (moves to processing)
	msg, _, err := queue.AcquireNext()
	if err != nil {
		t.Fatalf("AcquireNext failed: %v", err)
	}
	if msg == nil {
		t.Fatal("Expected message, got nil")
	}

	// Mark as permanent failure (simulating 5xx SMTP error)
	err = queue.MarkPermanentFailure(msg.ID, "550 Mailbox not found")
	if err != nil {
		t.Fatalf("MarkPermanentFailure failed: %v", err)
	}

	// Verify message moved directly to failed (not retried)
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if pending != 0 {
		t.Errorf("Expected 0 pending (no retry), got %d", pending)
	}
	if processing != 0 {
		t.Errorf("Expected 0 processing, got %d", processing)
	}
	if failed != 1 {
		t.Errorf("Expected 1 failed, got %d", failed)
	}

	// Verify metadata contains "PERMANENT" marker in errors
	entries, err := os.ReadDir(queue.failedDir)
	if err != nil {
		t.Fatalf("Failed to read failed directory: %v", err)
	}

	var metadata QueuedMessage
	found := false
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".json" {
			path := filepath.Join(queue.failedDir, entry.Name())
			if err := queue.readMetadata(path, &metadata); err == nil {
				found = true
				break
			}
		}
	}

	if !found {
		t.Fatal("Failed message metadata not found")
	}

	if metadata.Attempts != 1 {
		t.Errorf("Expected 1 attempt (no retry), got %d", metadata.Attempts)
	}

	if len(metadata.Errors) != 1 {
		t.Fatalf("Expected 1 error, got %d", len(metadata.Errors))
	}

	// Check that error contains "PERMANENT" marker
	errorMsg := metadata.Errors[0]
	if !strings.Contains(errorMsg, "PERMANENT") {
		t.Errorf("Expected error to contain 'PERMANENT', got: %s", errorMsg)
	}
	if !strings.Contains(errorMsg, "550 Mailbox not found") {
		t.Errorf("Expected error to contain '550 Mailbox not found', got: %s", errorMsg)
	}
}

// TestMarkPermanentFailureVsTemporaryFailure tests the difference between permanent and temporary failures
func TestMarkPermanentFailureVsTemporaryFailure(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 3, []time.Duration{100 * time.Millisecond})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Enqueue two messages
	err = queue.Enqueue("sender1@example.com", "recipient1@example.com", "redirect", []byte("Permanent failure test"))
	if err != nil {
		t.Fatalf("Enqueue 1 failed: %v", err)
	}

	err = queue.Enqueue("sender2@example.com", "recipient2@example.com", "redirect", []byte("Temporary failure test"))
	if err != nil {
		t.Fatalf("Enqueue 2 failed: %v", err)
	}

	// Acquire first message and mark as permanent failure (5xx)
	msg1, _, err := queue.AcquireNext()
	if err != nil || msg1 == nil {
		t.Fatalf("AcquireNext 1 failed: %v", err)
	}
	err = queue.MarkPermanentFailure(msg1.ID, "550 User not found")
	if err != nil {
		t.Fatalf("MarkPermanentFailure failed: %v", err)
	}

	// Acquire second message and mark as temporary failure (4xx)
	msg2, _, err := queue.AcquireNext()
	if err != nil || msg2 == nil {
		t.Fatalf("AcquireNext 2 failed: %v", err)
	}
	err = queue.MarkFailure(msg2.ID, "450 Mailbox busy")
	if err != nil {
		t.Fatalf("MarkFailure failed: %v", err)
	}

	// Check stats: permanent should be in failed, temporary should be in pending (for retry)
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if pending != 1 {
		t.Errorf("Expected 1 pending (temporary failure queued for retry), got %d", pending)
	}
	if processing != 0 {
		t.Errorf("Expected 0 processing, got %d", processing)
	}
	if failed != 1 {
		t.Errorf("Expected 1 failed (permanent failure), got %d", failed)
	}
}

// TestRecoverOrphanedMessages tests crash recovery functionality
func TestRecoverOrphanedMessages(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Enqueue 3 messages
	for i := 1; i <= 3; i++ {
		err = queue.Enqueue(
			"sender@example.com",
			"recipient@example.com",
			"redirect",
			[]byte("Test message "+string(rune('0'+i))),
		)
		if err != nil {
			t.Fatalf("Enqueue %d failed: %v", i, err)
		}
	}

	// Simulate crash by acquiring messages but not marking them
	msg1, _, err := queue.AcquireNext()
	if err != nil || msg1 == nil {
		t.Fatalf("AcquireNext 1 failed: %v", err)
	}
	msg2, _, err := queue.AcquireNext()
	if err != nil || msg2 == nil {
		t.Fatalf("AcquireNext 2 failed: %v", err)
	}

	// Verify state before recovery
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if pending != 1 || processing != 2 || failed != 0 {
		t.Errorf("Expected pending=1 processing=2 failed=0, got pending=%d processing=%d failed=%d",
			pending, processing, failed)
	}

	// Recover orphaned messages (simulates restart after crash)
	recovered, err := queue.RecoverOrphanedMessages()
	if err != nil {
		t.Fatalf("RecoverOrphanedMessages failed: %v", err)
	}
	if recovered != 2 {
		t.Errorf("Expected 2 recovered messages, got %d", recovered)
	}

	// Verify all messages are back in pending
	pending, processing, failed, err = queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if pending != 3 || processing != 0 || failed != 0 {
		t.Errorf("Expected pending=3 processing=0 failed=0 after recovery, got pending=%d processing=%d failed=%d",
			pending, processing, failed)
	}

	// Verify messages can be acquired again after recovery
	msg, _, err := queue.AcquireNext()
	if err != nil || msg == nil {
		t.Fatalf("AcquireNext after recovery failed: %v", err)
	}
}

// TestRecoverOrphanedMessagesEmpty tests recovery with empty processing directory
func TestRecoverOrphanedMessagesEmpty(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Recovery should succeed with no messages
	recovered, err := queue.RecoverOrphanedMessages()
	if err != nil {
		t.Fatalf("RecoverOrphanedMessages failed: %v", err)
	}
	if recovered != 0 {
		t.Errorf("Expected 0 recovered messages, got %d", recovered)
	}
}

// TestCleanupOldFailedMessages tests cleanup of old failed messages
func TestCleanupOldFailedMessages(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 3, []time.Duration{100 * time.Millisecond})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Enqueue and fail 3 messages
	for i := 1; i <= 3; i++ {
		err = queue.Enqueue(
			"sender@example.com",
			"recipient@example.com",
			"redirect",
			[]byte("Test message "+string(rune('0'+i))),
		)
		if err != nil {
			t.Fatalf("Enqueue %d failed: %v", i, err)
		}

		// Acquire and mark as permanent failure
		msg, _, err := queue.AcquireNext()
		if err != nil || msg == nil {
			t.Fatalf("AcquireNext %d failed: %v", i, err)
		}
		err = queue.MarkPermanentFailure(msg.ID, "Test failure")
		if err != nil {
			t.Fatalf("MarkPermanentFailure %d failed: %v", i, err)
		}
	}

	// Verify all in failed
	_, _, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if failed != 3 {
		t.Errorf("Expected 3 failed messages, got %d", failed)
	}

	// Cleanup with 1 hour retention (nothing should be deleted yet)
	cleaned, err := queue.CleanupOldFailedMessages(1 * time.Hour)
	if err != nil {
		t.Fatalf("CleanupOldFailedMessages failed: %v", err)
	}
	if cleaned != 0 {
		t.Errorf("Expected 0 cleaned (too new), got %d", cleaned)
	}

	// Cleanup with 1 millisecond retention (all should be deleted)
	time.Sleep(5 * time.Millisecond) // Ensure messages are old enough
	cleaned, err = queue.CleanupOldFailedMessages(1 * time.Millisecond)
	if err != nil {
		t.Fatalf("CleanupOldFailedMessages failed: %v", err)
	}
	if cleaned != 3 {
		t.Errorf("Expected 3 cleaned messages, got %d", cleaned)
	}

	// Verify failed count is now 0
	_, _, failed, err = queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if failed != 0 {
		t.Errorf("Expected 0 failed messages after cleanup, got %d", failed)
	}
}

// TestCleanupOldFailedMessagesEmpty tests cleanup with no failed messages
func TestCleanupOldFailedMessagesEmpty(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Cleanup should succeed with no messages
	cleaned, err := queue.CleanupOldFailedMessages(168 * time.Hour)
	if err != nil {
		t.Fatalf("CleanupOldFailedMessages failed: %v", err)
	}
	if cleaned != 0 {
		t.Errorf("Expected 0 cleaned messages, got %d", cleaned)
	}
}

// TestCleanupDisabledWithZeroRetention tests that cleanup is disabled when retention is 0
func TestCleanupDisabledWithZeroRetention(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 3, []time.Duration{100 * time.Millisecond})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Enqueue and fail 3 messages
	for i := 1; i <= 3; i++ {
		err = queue.Enqueue(
			"sender@example.com",
			"recipient@example.com",
			"redirect",
			[]byte("Test message "+string(rune('0'+i))),
		)
		if err != nil {
			t.Fatalf("Enqueue %d failed: %v", i, err)
		}

		msg, _, err := queue.AcquireNext()
		if err != nil || msg == nil {
			t.Fatalf("AcquireNext %d failed: %v", i, err)
		}
		err = queue.MarkPermanentFailure(msg.ID, "Test failure")
		if err != nil {
			t.Fatalf("MarkPermanentFailure %d failed: %v", i, err)
		}
	}

	// Verify all in failed
	_, _, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if failed != 3 {
		t.Errorf("Expected 3 failed messages, got %d", failed)
	}

	// Cleanup with 0 retention (should not delete anything)
	time.Sleep(5 * time.Millisecond) // Ensure messages are "old"
	cleaned, err := queue.CleanupOldFailedMessages(0)
	if err != nil {
		t.Fatalf("CleanupOldFailedMessages with 0 retention failed: %v", err)
	}
	if cleaned != 0 {
		t.Errorf("Expected 0 cleaned (cleanup disabled), got %d", cleaned)
	}

	// Verify all messages still in failed
	_, _, failed, err = queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if failed != 3 {
		t.Errorf("Expected 3 failed messages (cleanup disabled), got %d", failed)
	}
}
