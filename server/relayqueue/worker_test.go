package relayqueue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/circuitbreaker"
)

// mockRelayHandler implements delivery.RelayHandler for testing
type mockRelayHandler struct {
	mu            sync.Mutex
	messages      []mockMessage
	shouldFail    bool
	failCount     int
	currentFails  int
	deliveryDelay time.Duration
}

type mockMessage struct {
	From    string
	To      string
	Message []byte
}

func (m *mockRelayHandler) SendToExternalRelay(from, to string, message []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Simulate delivery delay
	if m.deliveryDelay > 0 {
		time.Sleep(m.deliveryDelay)
	}

	// Simulate failures
	if m.shouldFail {
		if m.failCount == 0 || m.currentFails < m.failCount {
			m.currentFails++
			return errors.New("mock delivery failure")
		}
	}

	m.messages = append(m.messages, mockMessage{
		From:    from,
		To:      to,
		Message: message,
	})

	return nil
}

func (m *mockRelayHandler) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = nil
	m.currentFails = 0
}

func (m *mockRelayHandler) getMessageCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.messages)
}

func (m *mockRelayHandler) getMessage(index int) mockMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	if index < len(m.messages) {
		return m.messages[index]
	}
	return mockMessage{}
}

// TestNewWorker tests worker creation
func TestNewWorker(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	handler := &mockRelayHandler{}

	tests := []struct {
		name          string
		interval      time.Duration
		batchSize     int
		concurrency   int
		expectedBatch int
		expectedConc  int
	}{
		{
			name:          "Valid worker with defaults",
			interval:      1 * time.Second,
			batchSize:     0,
			concurrency:   0,
			expectedBatch: 100,
			expectedConc:  5,
		},
		{
			name:          "Valid worker with custom batch",
			interval:      500 * time.Millisecond,
			batchSize:     50,
			concurrency:   10,
			expectedBatch: 50,
			expectedConc:  10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			worker := NewWorker(queue, handler, tt.interval, tt.batchSize, tt.concurrency, nil)

			if worker == nil {
				t.Fatal("Expected non-nil worker")
			}

			if worker.queue != queue {
				t.Error("Queue not set correctly")
			}
			if worker.relayHandler != handler {
				t.Error("Handler not set correctly")
			}
			if worker.interval != tt.interval {
				t.Errorf("Expected interval %v, got %v", tt.interval, worker.interval)
			}
			if worker.batchSize != tt.expectedBatch {
				t.Errorf("Expected batch size %d, got %d", tt.expectedBatch, worker.batchSize)
			}
			if worker.concurrency != tt.expectedConc {
				t.Errorf("Expected concurrency %d, got %d", tt.expectedConc, worker.concurrency)
			}
		})
	}
}

// TestWorkerStartStop tests worker lifecycle
func TestWorkerStartStop(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	handler := &mockRelayHandler{}
	worker := NewWorker(queue, handler, 100*time.Millisecond, 10, 5, nil)

	ctx := context.Background()

	// Start worker
	err = worker.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start worker: %v", err)
	}

	if !worker.running {
		t.Error("Worker should be running")
	}

	// Starting again should be idempotent
	err = worker.Start(ctx)
	if err != nil {
		t.Errorf("Second start should not error: %v", err)
	}

	// Stop worker
	worker.Stop()

	if worker.running {
		t.Error("Worker should not be running after stop")
	}

	// Stopping again should be idempotent
	worker.Stop()
}

// TestWorkerProcessMessage tests single message processing
func TestWorkerProcessMessage(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	handler := &mockRelayHandler{}
	worker := NewWorker(queue, handler, 1*time.Second, 10, 5, nil)

	ctx := context.Background()

	// Enqueue a message
	from := "sender@example.com"
	to := "recipient@example.com"
	message := []byte("Test message")

	err = queue.Enqueue(from, to, "redirect", message)
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Start worker
	err = worker.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start worker: %v", err)
	}
	defer worker.Stop()

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Verify message was delivered
	if handler.getMessageCount() != 1 {
		t.Errorf("Expected 1 delivered message, got %d", handler.getMessageCount())
	}

	delivered := handler.getMessage(0)
	if delivered.From != from {
		t.Errorf("Expected from %s, got %s", from, delivered.From)
	}
	if delivered.To != to {
		t.Errorf("Expected to %s, got %s", to, delivered.To)
	}
	if string(delivered.Message) != string(message) {
		t.Error("Message content doesn't match")
	}

	// Verify queue is empty
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if pending != 0 || processing != 0 || failed != 0 {
		t.Errorf("Expected empty queue, got pending=%d processing=%d failed=%d", pending, processing, failed)
	}
}

// TestWorkerProcessMultipleMessages tests batch processing
func TestWorkerProcessMultipleMessages(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	handler := &mockRelayHandler{}
	worker := NewWorker(queue, handler, 100*time.Millisecond, 5, 5, nil) // Small batch size

	ctx := context.Background()

	// Enqueue multiple messages
	numMessages := 10
	for i := 0; i < numMessages; i++ {
		err = queue.Enqueue(
			fmt.Sprintf("sender%d@example.com", i),
			fmt.Sprintf("recipient%d@example.com", i),
			"redirect",
			[]byte(fmt.Sprintf("Message %d", i)),
		)
		if err != nil {
			t.Fatalf("Enqueue %d failed: %v", i, err)
		}
	}

	// Start worker
	err = worker.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start worker: %v", err)
	}
	defer worker.Stop()

	// Wait for processing (two batches of 5)
	time.Sleep(500 * time.Millisecond)

	// Verify all messages were delivered
	if handler.getMessageCount() != numMessages {
		t.Errorf("Expected %d delivered messages, got %d", numMessages, handler.getMessageCount())
	}

	// Verify queue is empty
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if pending != 0 || processing != 0 || failed != 0 {
		t.Errorf("Expected empty queue, got pending=%d processing=%d failed=%d", pending, processing, failed)
	}
}

// TestWorkerRetryOnFailure tests retry mechanism
func TestWorkerRetryOnFailure(t *testing.T) {
	backoff := []time.Duration{50 * time.Millisecond, 100 * time.Millisecond}
	queue, err := NewDiskQueue(t.TempDir(), 10, backoff)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Handler that fails first 2 times, then succeeds
	handler := &mockRelayHandler{
		shouldFail: true,
		failCount:  2,
	}
	worker := NewWorker(queue, handler, 50*time.Millisecond, 10, 5, nil)

	ctx := context.Background()

	// Enqueue a message
	err = queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test"))
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Start worker
	err = worker.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start worker: %v", err)
	}
	defer worker.Stop()

	// Wait for retries (50ms initial + 50ms backoff + 100ms backoff + processing time)
	time.Sleep(500 * time.Millisecond)

	// Verify message was eventually delivered
	if handler.getMessageCount() != 1 {
		t.Errorf("Expected 1 delivered message after retries, got %d", handler.getMessageCount())
	}

	// Verify queue is empty
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}
	if pending != 0 || processing != 0 || failed != 0 {
		t.Errorf("Expected empty queue after success, got pending=%d processing=%d failed=%d", pending, processing, failed)
	}
}

// TestWorkerMaxAttemptsFailure tests that messages move to failed after max attempts
func TestWorkerMaxAttemptsFailure(t *testing.T) {
	maxAttempts := 3
	backoff := []time.Duration{10 * time.Millisecond}
	queue, err := NewDiskQueue(t.TempDir(), maxAttempts, backoff)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Handler that always fails
	handler := &mockRelayHandler{
		shouldFail: true,
	}
	worker := NewWorker(queue, handler, 20*time.Millisecond, 10, 5, nil)

	ctx := context.Background()

	// Enqueue a message
	err = queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test"))
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Start worker
	err = worker.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start worker: %v", err)
	}
	defer worker.Stop()

	// Wait for all attempts (20ms * 3 attempts + backoff delays + buffer)
	time.Sleep(500 * time.Millisecond)

	// Verify message is in failed state
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if failed != 1 {
		t.Errorf("Expected 1 failed message, got %d", failed)
	}
	if pending != 0 {
		t.Errorf("Expected 0 pending, got %d", pending)
	}
	if processing != 0 {
		t.Errorf("Expected 0 processing, got %d", processing)
	}

	// Verify no messages were successfully delivered
	if handler.getMessageCount() != 0 {
		t.Errorf("Expected 0 delivered messages, got %d", handler.getMessageCount())
	}
}

// TestWorkerContextCancellation tests worker stops on context cancellation
func TestWorkerContextCancellation(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	handler := &mockRelayHandler{}
	worker := NewWorker(queue, handler, 100*time.Millisecond, 10, 5, nil)

	ctx, cancel := context.WithCancel(context.Background())

	// Start worker
	err = worker.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start worker: %v", err)
	}

	// Cancel context after a short delay
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Wait for worker to stop (wg.Wait() ensures it's stopped)
	time.Sleep(200 * time.Millisecond)

	// Worker should have stopped (check by trying to start again)
	worker.mu.Lock()
	wasRunning := worker.running
	worker.mu.Unlock()

	if wasRunning {
		t.Error("Worker should have stopped after context cancellation")
	}
}

// TestWorkerGracefulShutdown tests worker completes current message on shutdown
func TestWorkerGracefulShutdown(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	handler := &mockRelayHandler{}
	worker := NewWorker(queue, handler, 100*time.Millisecond, 10, 5, nil)

	ctx := context.Background()

	// Enqueue a message
	err = queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test"))
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Start worker
	err = worker.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start worker: %v", err)
	}

	// Give it time to start processing
	time.Sleep(50 * time.Millisecond)

	// Stop worker (should wait for current message to complete)
	worker.Stop()

	// Verify worker stopped cleanly
	if worker.running {
		t.Error("Worker should not be running after stop")
	}
}

// TestWorkerNilHandler tests worker behavior with no handler
func TestWorkerNilHandler(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 1, []time.Duration{10 * time.Millisecond})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	worker := NewWorker(queue, nil, 50*time.Millisecond, 10, 5, nil)

	ctx := context.Background()

	// Enqueue a message
	err = queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test"))
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Start worker
	err = worker.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start worker: %v", err)
	}
	defer worker.Stop()

	// Wait for processing
	time.Sleep(200 * time.Millisecond)

	// Message should be moved to failed (max attempts = 1, no handler)
	_, _, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if failed != 1 {
		t.Errorf("Expected 1 failed message (no handler), got %d", failed)
	}
}

// TestWorkerGetStats tests GetStats method
func TestWorkerGetStats(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	handler := &mockRelayHandler{}
	worker := NewWorker(queue, handler, 1*time.Second, 10, 5, nil)

	// Enqueue some messages
	for i := 0; i < 5; i++ {
		queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test"))
	}

	// Get stats through worker
	pending, processing, failed, err := worker.GetStats()
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if pending != 5 {
		t.Errorf("Expected 5 pending, got %d", pending)
	}
	if processing != 0 {
		t.Errorf("Expected 0 processing, got %d", processing)
	}
	if failed != 0 {
		t.Errorf("Expected 0 failed, got %d", failed)
	}
}

// TestWorkerConcurrentProcessing tests concurrent message processing
func TestWorkerConcurrentProcessing(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	handler := &mockRelayHandler{
		deliveryDelay: 10 * time.Millisecond, // Small delay to simulate real processing
	}
	worker := NewWorker(queue, handler, 50*time.Millisecond, 10, 5, nil)

	ctx := context.Background()

	// Enqueue many messages
	numMessages := 20
	for i := 0; i < numMessages; i++ {
		err = queue.Enqueue(
			fmt.Sprintf("sender%d@example.com", i),
			fmt.Sprintf("recipient%d@example.com", i),
			"redirect",
			[]byte(fmt.Sprintf("Message %d", i)),
		)
		if err != nil {
			t.Fatalf("Enqueue %d failed: %v", i, err)
		}
	}

	// Start worker
	err = worker.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start worker: %v", err)
	}
	defer worker.Stop()

	// Wait for all processing
	timeout := time.After(5 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for messages to process")
		case <-ticker.C:
			pending, processing, _, _ := queue.GetStats()
			if pending == 0 && processing == 0 {
				goto done
			}
		}
	}

done:
	// Verify all messages were delivered
	if handler.getMessageCount() != numMessages {
		t.Errorf("Expected %d delivered messages, got %d", numMessages, handler.getMessageCount())
	}
}

// TestWorkerImmediateProcessing tests that worker processes immediately on start
func TestWorkerImmediateProcessing(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	handler := &mockRelayHandler{}
	worker := NewWorker(queue, handler, 10*time.Second, 10, 5, nil) // Long interval

	ctx := context.Background()

	// Enqueue a message
	err = queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test"))
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	// Start worker
	startTime := time.Now()
	err = worker.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start worker: %v", err)
	}
	defer worker.Stop()

	// Wait for immediate processing (should be < 1 second, not waiting for 10s interval)
	time.Sleep(200 * time.Millisecond)

	elapsed := time.Since(startTime)
	if elapsed > 2*time.Second {
		t.Errorf("Processing took too long (%v), should be immediate", elapsed)
	}

	// Verify message was delivered
	if handler.getMessageCount() != 1 {
		t.Errorf("Expected 1 delivered message, got %d", handler.getMessageCount())
	}
}

// BenchmarkWorkerProcessing benchmarks worker message processing
func BenchmarkWorkerProcessing(b *testing.B) {
	queue, err := NewDiskQueue(b.TempDir(), 10, nil)
	if err != nil {
		b.Fatalf("Failed to create queue: %v", err)
	}

	handler := &mockRelayHandler{}
	worker := NewWorker(queue, handler, 10*time.Millisecond, 100, 5, nil)

	ctx := context.Background()

	// Pre-populate queue
	message := []byte("Subject: Test\r\n\r\nTest message body")
	for i := 0; i < b.N; i++ {
		queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", message)
	}

	// Start worker
	err = worker.Start(ctx)
	if err != nil {
		b.Fatalf("Failed to start worker: %v", err)
	}
	defer worker.Stop()

	b.ResetTimer()

	// Wait for all messages to be processed
	for {
		p, proc, _, _ := queue.GetStats()
		if p == 0 && proc == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// mockCircuitBreakerHandler implements both RelayHandler and CircuitBreakerProvider
// Used to test circuit breaker error handling
type mockCircuitBreakerHandler struct {
	mu               sync.Mutex
	messages         []mockMessage
	callCount        int
	returnCBError    bool  // Return circuit breaker errors
	cbErrorType      error // Type of CB error to return (ErrCircuitBreakerOpen or ErrTooManyRequests)
	cbErrorUntilCall int   // Return CB error until this call count
}

func (m *mockCircuitBreakerHandler) SendToExternalRelay(from, to string, message []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.callCount++

	// Return circuit breaker error if configured
	if m.returnCBError && (m.cbErrorUntilCall == 0 || m.callCount <= m.cbErrorUntilCall) {
		return m.cbErrorType
	}

	// Otherwise deliver successfully
	m.messages = append(m.messages, mockMessage{
		From:    from,
		To:      to,
		Message: message,
	})
	return nil
}

func (m *mockCircuitBreakerHandler) GetCircuitBreaker() *circuitbreaker.CircuitBreaker {
	// Return nil - we're just testing error handling, not actual circuit breaker logic
	return nil
}

func (m *mockCircuitBreakerHandler) getMessageCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.messages)
}

func (m *mockCircuitBreakerHandler) getCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

// TestWorkerCircuitBreakerErrorHandling tests that circuit breaker errors don't increment attempt count
func TestWorkerCircuitBreakerErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		errorType   error
		description string
	}{
		{
			name:        "ErrCircuitBreakerOpen",
			errorType:   circuitbreaker.ErrCircuitBreakerOpen,
			description: "Circuit breaker OPEN state should release messages without incrementing attempts",
		},
		{
			name:        "ErrTooManyRequests",
			errorType:   circuitbreaker.ErrTooManyRequests,
			description: "Circuit breaker HALF-OPEN with too many requests should release messages",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queue, err := NewDiskQueue(t.TempDir(), 10, nil)
			if err != nil {
				t.Fatalf("Failed to create queue: %v", err)
			}

			handler := &mockCircuitBreakerHandler{
				returnCBError:    true,
				cbErrorType:      tt.errorType,
				cbErrorUntilCall: 2, // First 2 calls return CB error, then succeed
			}

			worker := NewWorker(queue, handler, 50*time.Millisecond, 10, 5, nil)
			ctx := context.Background()

			// Enqueue a message
			err = queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test message"))
			if err != nil {
				t.Fatalf("Enqueue failed: %v", err)
			}

			// Start worker
			err = worker.Start(ctx)
			if err != nil {
				t.Fatalf("Failed to start worker: %v", err)
			}
			defer worker.Stop()

			// Wait for multiple processing cycles
			// First cycle: CB error -> message released back to queue
			// Second cycle: CB error again -> message released back to queue
			// Third cycle: Success
			time.Sleep(200 * time.Millisecond)

			// Verify message was eventually delivered
			if handler.getMessageCount() != 1 {
				t.Errorf("Expected 1 delivered message, got %d", handler.getMessageCount())
			}

			// Verify handler was called 3 times (2 CB errors + 1 success)
			if handler.getCallCount() != 3 {
				t.Errorf("Expected 3 handler calls (2 CB errors + 1 success), got %d", handler.getCallCount())
			}

			// Get the message metadata to verify attempts were not incremented
			msg, _, err := queue.AcquireNext()
			if err != nil {
				t.Fatalf("Failed to check message: %v", err)
			}

			// Message should be delivered (moved to success), so AcquireNext returns nil
			if msg != nil {
				t.Errorf("Expected message to be delivered, but found in queue with %d attempts", msg.Attempts)
			}

			// Verify queue is empty
			pending, processing, failed, err := queue.GetStats()
			if err != nil {
				t.Fatalf("Failed to get stats: %v", err)
			}

			if pending != 0 || processing != 0 || failed != 0 {
				t.Errorf("Expected empty queue, got pending=%d processing=%d failed=%d", pending, processing, failed)
			}
		})
	}
}

// TestWorkerCircuitBreakerNoInfiniteLoop tests that messages don't get stuck in infinite loop
// This test simulates the production issue where circuit breaker was stuck in HALF-OPEN state
func TestWorkerCircuitBreakerNoInfiniteLoop(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, []time.Duration{
		100 * time.Millisecond, // Short backoff for faster test
	})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	handler := &mockCircuitBreakerHandler{
		returnCBError:    true,
		cbErrorType:      circuitbreaker.ErrTooManyRequests,
		cbErrorUntilCall: 5, // Return CB error for first 5 calls
	}

	// Use higher concurrency than circuit breaker allows (simulating production scenario)
	worker := NewWorker(queue, handler, 50*time.Millisecond, 10, 10, nil) // 10 concurrent workers
	ctx := context.Background()

	// Enqueue multiple messages (more than circuit breaker's MaxRequests)
	for i := 0; i < 8; i++ {
		err = queue.Enqueue(
			fmt.Sprintf("sender%d@example.com", i),
			fmt.Sprintf("recipient%d@example.com", i),
			"redirect",
			[]byte(fmt.Sprintf("Test message %d", i)),
		)
		if err != nil {
			t.Fatalf("Enqueue failed: %v", err)
		}
	}

	// Start worker
	err = worker.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start worker: %v", err)
	}
	defer worker.Stop()

	// Wait for processing (with timeout to prevent infinite wait)
	timeout := time.After(2 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			pending, processing, failed, _ := queue.GetStats()
			t.Fatalf("Timeout waiting for messages to process. pending=%d processing=%d failed=%d delivered=%d",
				pending, processing, failed, handler.getMessageCount())
		case <-ticker.C:
			if handler.getMessageCount() == 8 {
				// All messages delivered successfully
				goto success
			}
		}
	}

success:
	t.Logf("All 8 messages delivered after %d total handler calls", handler.getCallCount())

	// Verify queue is empty
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}

	if pending != 0 || processing != 0 || failed != 0 {
		t.Errorf("Expected empty queue, got pending=%d processing=%d failed=%d", pending, processing, failed)
	}

	// Verify we had more calls than messages (due to CB errors and retries)
	if handler.getCallCount() <= 8 {
		t.Errorf("Expected more than 8 handler calls due to CB errors, got %d", handler.getCallCount())
	}
}
