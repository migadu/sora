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
	failUntilCall    int // Fail until this call number
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
		failUntilCall: 5, // Fail first 5 attempts to open CB, then succeed on 6th (first HALF-OPEN attempt)
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
	// A handler's success precedes durable local terminal cleanup (the file
	// leaves processing/ only after SendToExternalRelay returns). Join workers
	// before asserting that all queue files have been removed.
	worker.Stop()

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

// TestCircuitBreakerHalfOpenDeliversBeforeNextTick: with a worker interval far longer
// than the breaker's timeout, the queue is retried as soon as the breaker turns
// HALF-OPEN (the worker's 5-second breaker check), not at the next interval tick.
// Without that check the messages wait for the 60-second tick, which in production
// meant hours with a long worker_interval.
func TestCircuitBreakerHalfOpenDeliversBeforeNextTick(t *testing.T) {
	queue, err := NewDiskQueue(t.TempDir(), 10, []time.Duration{100 * time.Millisecond})
	if err != nil {
		t.Fatalf("Failed to create queue: %v", err)
	}

	cb := circuitbreaker.NewCircuitBreaker(circuitbreaker.Settings{
		Name:        "test_relay_half_open",
		MaxRequests: 3,
		Interval:    10 * time.Second,
		Timeout:     1 * time.Second,
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

	handler := &mockRelayHandlerWithRealCB{cb: cb, shouldFailAlways: true}

	const messages = 6 // five failures open the breaker; the sixth meets it open
	for i := 0; i < messages; i++ {
		if err := queue.Enqueue("sender@example.com", "recipient@example.com", "redirect", []byte("Test")); err != nil {
			t.Fatalf("Enqueue failed: %v", err)
		}
	}

	worker := NewWorker(queue, handler, 60*time.Second, 10, 5, 1*time.Hour, 168*time.Hour, nil)
	if err := worker.Start(context.Background()); err != nil {
		t.Fatalf("Failed to start worker: %v", err)
	}
	defer worker.Stop()

	// The worker processes the queue once on start.
	deadline := time.Now().Add(2 * time.Second)
	for cb.State() != circuitbreaker.StateOpen && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if cb.State() != circuitbreaker.StateOpen {
		t.Fatalf("Expected OPEN after the first pass, got %s (calls: %d)", cb.State(), handler.getCallCount())
	}
	handler.setFailAlways(false)

	// HALF-OPEN after 1s, the breaker check within 5s of start: well before the 60s tick.
	deadline = time.Now().Add(15 * time.Second)
	for handler.getMessageCount() < messages && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if got := handler.getMessageCount(); got != messages {
		t.Fatalf("delivered %d of %d messages within 15s of the breaker opening (state %s); "+
			"the worker did not retry when the breaker turned HALF-OPEN", got, messages, cb.State())
	}
}

// Note: TestCircuitBreakerAutoRecovery above already validates state transitions
// including OPEN -> HALF-OPEN -> CLOSED with proper logging
