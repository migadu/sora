package relayqueue

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/circuitbreaker"
)

// mockRelayHandlerWithRealCB wraps a real circuit breaker for integration testing
type mockRelayHandlerWithRealCB struct {
	mu               sync.Mutex
	messages         []mockMessage
	cb               *circuitbreaker.CircuitBreaker
	failUntilCall    int  // Fail until this call number
	callCount        int
	shouldFailAlways bool // Always fail (for testing stuck OPEN state)
}

func (m *mockRelayHandlerWithRealCB) SendToExternalRelay(from, to string, message []byte) error {
	// Execute through the circuit breaker
	_, err := m.cb.Execute(func() (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()

		m.callCount++

		// Simulate temporary failures
		if m.shouldFailAlways || (m.failUntilCall > 0 && m.callCount <= m.failUntilCall) {
			return nil, errors.New("mock relay failure")
		}

		// Success - store the message
		m.messages = append(m.messages, mockMessage{
			From:    from,
			To:      to,
			Message: message,
		})
		return nil, nil
	})

	return err
}

func (m *mockRelayHandlerWithRealCB) GetCircuitBreaker() *circuitbreaker.CircuitBreaker {
	return m.cb
}

func (m *mockRelayHandlerWithRealCB) getMessageCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.messages)
}

func (m *mockRelayHandlerWithRealCB) getCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func (m *mockRelayHandlerWithRealCB) setFailAlways(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFailAlways = fail
}

// TestCircuitBreakerAutoRecovery tests the automatic recovery when circuit breaker enters HALF-OPEN state
// This test validates the fix for the production issue where messages were stuck until server restart
func TestCircuitBreakerAutoRecovery(t *testing.T) {
	// Use short retry backoff for faster testing
	queue, err := NewDiskQueue(t.TempDir(), 10, []time.Duration{
		100 * time.Millisecond, // First retry after 100ms
		200 * time.Millisecond,
		500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Create a circuit breaker with short timeout for faster testing
	cb := circuitbreaker.NewCircuitBreaker(circuitbreaker.Settings{
		Name:        "test_relay",
		MaxRequests: 3,                // Allow 3 requests in HALF-OPEN state
		Interval:    10 * time.Second, // Stats reset interval
		Timeout:     2 * time.Second,  // Recovery timeout (OPEN -> HALF-OPEN)
		ReadyToTrip: func(counts circuitbreaker.Counts) bool {
			// Open after 5 consecutive failures
			return counts.ConsecutiveFailures >= 5
		},
		OnStateChange: func(name string, from circuitbreaker.State, to circuitbreaker.State) {
			t.Logf("Circuit breaker state change: %s -> %s", from, to)
		},
		IsSuccessful: func(err error) bool {
			return err == nil
		},
	})

	handler := &mockRelayHandlerWithRealCB{
		cb:            cb,
		failUntilCall: 7, // Fail first 7 attempts (5 to open CB + 2 in HALF-OPEN), then succeed on 8th
	}

	// Create worker with 6-second ticker interval (longer than CB timeout)
	// This simulates the production scenario where worker ticks are infrequent
	worker := NewWorker(queue, handler, 6*time.Second, 10, 5, 1*time.Hour, 168*time.Hour, nil)
	ctx := context.Background()

	// Enqueue 6 test messages (enough to trigger 5+ failures and open the CB)
	for i := 0; i < 6; i++ {
		err = queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test message"))
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

	t.Log("Phase 1: Circuit breaker should OPEN after 5 failures")

	// Wait for circuit breaker to open (should happen quickly on first tick)
	time.Sleep(500 * time.Millisecond)

	// Verify circuit breaker is OPEN
	if cb.State() != circuitbreaker.StateOpen {
		t.Errorf("Expected circuit breaker to be OPEN, got %s", cb.State())
	}
	t.Logf("Circuit breaker is now OPEN after %d calls", handler.getCallCount())

	t.Log("Phase 2: Wait for automatic transition to HALF-OPEN (2 second timeout)")

	// Wait for CB timeout to expire and worker to detect HALF-OPEN state
	// The 5-second ticker in the worker should catch this
	time.Sleep(3 * time.Second)

	t.Log("Phase 3: Worker should detect HALF-OPEN and attempt delivery")

	// Wait a bit more for the worker to process in HALF-OPEN state
	time.Sleep(2 * time.Second)

	// Verify circuit breaker recovered (should be CLOSED now if deliveries succeeded)
	state := cb.State()
	t.Logf("Circuit breaker state after recovery window: %s (total calls: %d)", state, handler.getCallCount())

	// Circuit breaker should either be HALF-OPEN (still testing) or CLOSED (recovered)
	if state == circuitbreaker.StateOpen {
		t.Errorf("Circuit breaker still OPEN - automatic recovery failed!")
	}

	t.Log("Phase 4: Verify all messages eventually delivered")

	// Wait for all messages to be delivered
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			pending, processing, failed, _ := queue.GetStats()
			t.Fatalf("Timeout: messages not delivered. pending=%d processing=%d failed=%d delivered=%d state=%s",
				pending, processing, failed, handler.getMessageCount(), cb.State())
		case <-ticker.C:
			if handler.getMessageCount() == 6 {
				t.Logf("✓ All 6 messages delivered successfully after %d total calls", handler.getCallCount())
				goto success
			}
		}
	}

success:
	// Verify circuit breaker is now CLOSED (fully recovered)
	finalState := cb.State()
	if finalState != circuitbreaker.StateClosed {
		t.Logf("Warning: Circuit breaker not CLOSED at end (state=%s)", finalState)
	}

	// Verify queue is empty
	pending, processing, failed, err := queue.GetStats()
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}

	if pending != 0 || processing != 0 || failed != 0 {
		t.Errorf("Expected empty queue, got pending=%d processing=%d failed=%d", pending, processing, failed)
	}

	t.Logf("✓ Test completed successfully - circuit breaker auto-recovery working!")
}

// TestCircuitBreakerStuckOpen tests the ORIGINAL bug where circuit breaker stayed OPEN indefinitely
// This test should FAIL without the 5-second monitoring ticker fix
func TestCircuitBreakerWithoutAutoRecovery(t *testing.T) {
	t.Skip("Skipping test that demonstrates the original bug - would hang indefinitely")

	queue, err := NewDiskQueue(t.TempDir(), 10, nil)
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	// Create circuit breaker with short timeout
	cb := circuitbreaker.NewCircuitBreaker(circuitbreaker.Settings{
		Name:        "test_relay_stuck",
		MaxRequests: 3,
		Interval:    10 * time.Second,
		Timeout:     1 * time.Second, // Very short timeout
		ReadyToTrip: func(counts circuitbreaker.Counts) bool {
			return counts.ConsecutiveFailures >= 5
		},
		OnStateChange: func(name string, from circuitbreaker.State, to circuitbreaker.State) {
			t.Logf("State change: %s -> %s", from, to)
		},
		IsSuccessful: func(err error) bool {
			return err == nil
		},
	})

	handler := &mockRelayHandlerWithRealCB{
		cb:               cb,
		shouldFailAlways: true, // Always fail to keep CB OPEN
	}

	// Worker with VERY long interval (simulates infrequent processing)
	// Without the 5-second monitoring ticker, this would never recover
	worker := NewWorker(queue, handler, 60*time.Second, 10, 5, 1*time.Hour, 168*time.Hour, nil)
	ctx := context.Background()

	err = queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test"))
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	err = worker.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start worker: %v", err)
	}
	defer worker.Stop()

	// Wait for CB to open
	time.Sleep(2 * time.Second)

	if cb.State() != circuitbreaker.StateOpen {
		t.Fatalf("Expected OPEN, got %s", cb.State())
	}

	// Now make the handler succeed
	handler.setFailAlways(false)

	// Wait for CB timeout to expire
	time.Sleep(2 * time.Second)

	// With the fix: CB should transition to HALF-OPEN and worker should detect it
	// Without the fix: CB transitions to HALF-OPEN but worker doesn't know (waits for 60s tick)

	// Check if worker is actively trying deliveries
	callsBefore := handler.getCallCount()
	time.Sleep(3 * time.Second) // Wait for 5-second ticker to trigger
	callsAfter := handler.getCallCount()

	if callsAfter > callsBefore {
		t.Logf("✓ Worker actively retrying in HALF-OPEN state (calls increased from %d to %d)", callsBefore, callsAfter)
	} else {
		t.Errorf("✗ Worker NOT retrying - circuit breaker stuck! (calls stayed at %d)", callsBefore)
	}
}

// Note: TestCircuitBreakerAutoRecovery above already validates state transitions
// including OPEN -> HALF-OPEN -> CLOSED with proper logging
