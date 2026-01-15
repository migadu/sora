package circuitbreaker

import (
	"errors"
	"testing"
	"time"
)

// TestForceHalfOpen verifies that ForceHalfOpen transitions the breaker to half-open state
func TestForceHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(Settings{
		Name:        "test-force-halfopen",
		MaxRequests: 3,
		Timeout:     5 * time.Second,
		ReadyToTrip: func(counts Counts) bool {
			return counts.ConsecutiveFailures >= 3
		},
	})

	// Start in closed state
	if cb.State() != StateClosed {
		t.Errorf("Expected initial state to be CLOSED, got %v", cb.State())
	}

	// Cause 3 failures to trip the breaker
	testErr := errors.New("test error")
	for i := 0; i < 3; i++ {
		_, _ = cb.Execute(func() (any, error) {
			return nil, testErr
		})
	}

	// Should now be open
	if cb.State() != StateOpen {
		t.Errorf("Expected state to be OPEN after failures, got %v", cb.State())
	}

	// Verify that requests fail immediately with ErrCircuitBreakerOpen
	_, err := cb.Execute(func() (any, error) {
		return "should not execute", nil
	})
	if !errors.Is(err, ErrCircuitBreakerOpen) {
		t.Errorf("Expected ErrCircuitBreakerOpen, got %v", err)
	}

	// Force to half-open
	cb.ForceHalfOpen()

	// Should now be half-open
	if cb.State() != StateHalfOpen {
		t.Errorf("Expected state to be HALF_OPEN after ForceHalfOpen, got %v", cb.State())
	}

	// Should allow requests to pass through now
	result, err := cb.Execute(func() (any, error) {
		return "success", nil
	})
	if err != nil {
		t.Errorf("Expected request to succeed in HALF_OPEN state, got error: %v", err)
	}
	if result != "success" {
		t.Errorf("Expected result 'success', got %v", result)
	}

	// After a successful request, should transition back to closed
	if cb.State() != StateClosed {
		t.Errorf("Expected state to be CLOSED after successful request in HALF_OPEN, got %v", cb.State())
	}
}

// TestForceHalfOpenIdempotent verifies that calling ForceHalfOpen multiple times is safe
func TestForceHalfOpenIdempotent(t *testing.T) {
	cb := NewCircuitBreaker(Settings{
		Name:        "test-force-halfopen-idempotent",
		MaxRequests: 2,
		Timeout:     5 * time.Second,
		ReadyToTrip: func(counts Counts) bool {
			return counts.ConsecutiveFailures >= 2
		},
	})

	// Trip the breaker
	testErr := errors.New("test error")
	for i := 0; i < 2; i++ {
		_, _ = cb.Execute(func() (any, error) {
			return nil, testErr
		})
	}

	if cb.State() != StateOpen {
		t.Fatalf("Expected state to be OPEN, got %v", cb.State())
	}

	// Call ForceHalfOpen multiple times
	cb.ForceHalfOpen()
	cb.ForceHalfOpen()
	cb.ForceHalfOpen()

	// Should still be half-open
	if cb.State() != StateHalfOpen {
		t.Errorf("Expected state to be HALF_OPEN after multiple ForceHalfOpen calls, got %v", cb.State())
	}
}

// TestCircuitBreakerRecovery simulates database recovery scenario
func TestCircuitBreakerRecovery(t *testing.T) {
	stateChanges := []string{}
	cb := NewCircuitBreaker(Settings{
		Name:        "test-db-recovery",
		MaxRequests: 3,
		Timeout:     1 * time.Second, // Short timeout for testing
		ReadyToTrip: func(counts Counts) bool {
			return counts.ConsecutiveFailures >= 3
		},
		OnStateChange: func(name string, from State, to State) {
			stateChanges = append(stateChanges, from.String()+"->"+to.String())
		},
	})

	// Simulate database failures
	dbErr := errors.New("database connection failed")
	for i := 0; i < 3; i++ {
		_, _ = cb.Execute(func() (any, error) {
			return nil, dbErr
		})
	}

	// Circuit breaker should be OPEN
	if cb.State() != StateOpen {
		t.Fatalf("Expected OPEN state, got %v", cb.State())
	}

	// Requests should fail immediately
	_, err := cb.Execute(func() (any, error) {
		return "should not run", nil
	})
	if !errors.Is(err, ErrCircuitBreakerOpen) {
		t.Errorf("Expected ErrCircuitBreakerOpen, got %v", err)
	}

	// Simulate health check detecting database recovery
	// Health check calls ForceHalfOpen to immediately test recovery
	cb.ForceHalfOpen()

	if cb.State() != StateHalfOpen {
		t.Fatalf("Expected HALF_OPEN state after health check, got %v", cb.State())
	}

	// Next requests should succeed (database is now healthy)
	for i := 0; i < 3; i++ {
		result, err := cb.Execute(func() (any, error) {
			return "database is healthy", nil
		})
		if err != nil {
			t.Errorf("Request %d failed: %v", i, err)
		}
		if result != "database is healthy" {
			t.Errorf("Unexpected result: %v", result)
		}
	}

	// Circuit breaker should be CLOSED now
	if cb.State() != StateClosed {
		t.Errorf("Expected CLOSED state after successful requests, got %v", cb.State())
	}

	// Verify state transitions
	expectedTransitions := []string{
		"CLOSED->OPEN",      // After 3 failures
		"OPEN->HALF_OPEN",   // ForceHalfOpen called by health check
		"HALF_OPEN->CLOSED", // After first successful request in half-open
	}

	if len(stateChanges) != len(expectedTransitions) {
		t.Errorf("Expected %d state changes, got %d: %v", len(expectedTransitions), len(stateChanges), stateChanges)
	}

	for i, expected := range expectedTransitions {
		if i >= len(stateChanges) {
			break
		}
		if stateChanges[i] != expected {
			t.Errorf("State change %d: expected %s, got %s", i, expected, stateChanges[i])
		}
	}
}
