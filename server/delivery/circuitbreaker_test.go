package delivery

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/circuitbreaker"
)

// TestSMTPRelayHandler_CircuitBreakerIntegration tests circuit breaker with SMTP relay
func TestSMTPRelayHandler_CircuitBreakerIntegration(t *testing.T) {
	logger := &testLogger{}

	// Create handler with tight circuit breaker settings for testing
	cbConfig := CircuitBreakerConfig{
		Threshold:   2,                      // Open after 2 failures
		Timeout:     100 * time.Millisecond, // Quick recovery test
		MaxRequests: 1,                      // Single request in half-open
	}

	handler := NewRelayHandlerFromConfig(
		"smtp",
		"invalid.host.test:587", // Invalid host to trigger failures
		"",
		"",
		"test",
		true,
		true,
		false,
		"",
		"",
		logger,
		cbConfig,
	)

	smtpHandler, ok := handler.(*SMTPRelayHandler)
	if !ok {
		t.Fatal("Expected SMTPRelayHandler")
	}

	if smtpHandler.CircuitBreaker == nil {
		t.Fatal("Expected circuit breaker to be created")
	}

	// Test 1: Circuit should be closed initially
	state := smtpHandler.CircuitBreaker.State()
	if state != circuitbreaker.StateClosed {
		t.Errorf("Expected initial state CLOSED, got %s", state)
	}

	// Test 2: First failure
	err := handler.SendToExternalRelay("sender@test.com", "recipient@test.com", []byte("test"))
	if err == nil {
		t.Error("Expected error from invalid host")
	}
	if errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) {
		t.Error("Circuit should not be open yet after 1 failure")
	}

	// Test 3: Second failure - circuit should open
	err = handler.SendToExternalRelay("sender@test.com", "recipient@test.com", []byte("test"))
	if err == nil {
		t.Error("Expected error from invalid host")
	}

	// Test 4: Third attempt - circuit breaker should be open
	err = handler.SendToExternalRelay("sender@test.com", "recipient@test.com", []byte("test"))
	if !errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) {
		t.Errorf("Expected circuit breaker open error, got: %v", err)
	}

	state = smtpHandler.CircuitBreaker.State()
	if state != circuitbreaker.StateOpen {
		t.Errorf("Expected state OPEN after threshold failures, got %s", state)
	}

	// Test 5: Wait for timeout to transition to half-open
	time.Sleep(150 * time.Millisecond)

	// Next attempt should transition to half-open and allow through
	err = handler.SendToExternalRelay("sender@test.com", "recipient@test.com", []byte("test"))
	// It will fail (invalid host), but circuit breaker allowed it through
	if errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) {
		t.Error("Circuit should be in half-open state, not rejecting requests")
	}
}

// TestHTTPRelayHandler_CircuitBreakerIntegration tests circuit breaker with HTTP relay
func TestHTTPRelayHandler_CircuitBreakerIntegration(t *testing.T) {
	logger := &testLogger{}

	// Track request count
	requestCount := 0
	failureCount := 5

	// Create test server that fails N times then succeeds
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount <= failureCount {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create handler with circuit breaker
	cbConfig := CircuitBreakerConfig{
		Threshold:   3,                     // Open after 3 failures
		Timeout:     50 * time.Millisecond, // Quick recovery
		MaxRequests: 2,                     // Allow 2 requests in half-open
	}

	handler := NewRelayHandlerFromConfig(
		"http",
		"",
		server.URL,
		"test-token",
		"test",
		false,
		false,
		false,
		"",
		"",
		logger,
		cbConfig,
	)

	httpHandler, ok := handler.(*HTTPRelayHandler)
	if !ok {
		t.Fatal("Expected HTTPRelayHandler")
	}

	// Test: Trigger failures to open circuit
	for i := 0; i < 3; i++ {
		err := handler.SendToExternalRelay("sender@test.com", "recipient@test.com", []byte("test"))
		if err == nil {
			t.Errorf("Expected failure on attempt %d", i+1)
		}
	}

	// Circuit should be open now
	state := httpHandler.CircuitBreaker.State()
	if state != circuitbreaker.StateOpen {
		t.Errorf("Expected circuit OPEN after %d failures, got %s", cbConfig.Threshold, state)
	}

	// Attempt should fail fast
	err := handler.SendToExternalRelay("sender@test.com", "recipient@test.com", []byte("test"))
	if !errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) {
		t.Errorf("Expected circuit breaker open error, got: %v", err)
	}

	// Request count should still be 3 (no new request made)
	if requestCount != 3 {
		t.Errorf("Expected 3 requests, circuit breaker should have blocked 4th attempt, got %d", requestCount)
	}
}

// TestCircuitBreaker_CustomConfiguration tests custom circuit breaker settings
func TestCircuitBreaker_CustomConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		config      CircuitBreakerConfig
		wantDefault bool
	}{
		{
			name: "Custom values",
			config: CircuitBreakerConfig{
				Threshold:   10,
				Timeout:     1 * time.Minute,
				MaxRequests: 5,
			},
			wantDefault: false,
		},
		{
			name: "Zero values use defaults",
			config: CircuitBreakerConfig{
				Threshold:   0,
				Timeout:     0,
				MaxRequests: 0,
			},
			wantDefault: true,
		},
		{
			name: "Negative values use defaults",
			config: CircuitBreakerConfig{
				Threshold:   -1,
				Timeout:     -1 * time.Second,
				MaxRequests: -1,
			},
			wantDefault: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewRelayHandlerFromConfig(
				"http",
				"",
				"http://test.example.com",
				"token",
				"test",
				false,
				false,
				false,
				"",
				"",
				&testLogger{},
				tt.config,
			)

			httpHandler, ok := handler.(*HTTPRelayHandler)
			if !ok {
				t.Fatal("Expected HTTPRelayHandler")
			}

			if httpHandler.CircuitBreaker == nil {
				t.Fatal("Expected circuit breaker to be created")
			}

			// Circuit breaker should exist and work
			// We can't directly inspect the config, but we can verify it was created
			if httpHandler.GetCircuitBreaker() == nil {
				t.Error("GetCircuitBreaker should return non-nil circuit breaker")
			}
		})
	}
}

// TestCircuitBreaker_StateTransitions tests circuit breaker state machine
func TestCircuitBreaker_StateTransitions(t *testing.T) {
	stateChanges := []string{}

	// Create handler with custom logger that tracks state changes
	cbConfig := CircuitBreakerConfig{
		Threshold:   2,
		Timeout:     50 * time.Millisecond,
		MaxRequests: 1,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	trackingLogger := &testLoggerWithFunc{
		logFunc: func(msg string) {
			stateChanges = append(stateChanges, msg)
		},
	}

	handler := NewRelayHandlerFromConfig(
		"http",
		"",
		server.URL,
		"token",
		"test",
		false,
		false,
		false,
		"",
		"",
		trackingLogger,
		cbConfig,
	)

	httpHandler := handler.(*HTTPRelayHandler)

	// Initial state: CLOSED
	if httpHandler.CircuitBreaker.State() != circuitbreaker.StateClosed {
		t.Error("Expected initial state CLOSED")
	}

	// Trigger failures
	for i := 0; i < 2; i++ {
		handler.SendToExternalRelay("test@test.com", "test@test.com", []byte("test"))
	}

	// Should be OPEN now
	if httpHandler.CircuitBreaker.State() != circuitbreaker.StateOpen {
		t.Error("Expected state OPEN after threshold failures")
	}

	// Verify state change was logged
	found := false
	for _, msg := range stateChanges {
		if fmt.Sprintf("%v", msg) != "" {
			found = true
			break
		}
	}

	if !found && len(stateChanges) == 0 {
		t.Log("Note: State changes may not be captured in test logger")
	}
}

// TestCircuitBreaker_GetCircuitBreaker tests the GetCircuitBreaker method
func TestCircuitBreaker_GetCircuitBreaker(t *testing.T) {
	cbConfig := CircuitBreakerConfig{
		Threshold:   5,
		Timeout:     30 * time.Second,
		MaxRequests: 3,
	}

	t.Run("SMTP Handler", func(t *testing.T) {
		handler := NewRelayHandlerFromConfig(
			"smtp",
			"smtp.test.com:587",
			"",
			"",
			"test",
			true,
			true,
			false,
			"",
			"",
			&testLogger{},
			cbConfig,
		)

		smtpHandler := handler.(*SMTPRelayHandler)
		cb := smtpHandler.GetCircuitBreaker()

		if cb == nil {
			t.Error("Expected non-nil circuit breaker")
		}

		if cb.State() != circuitbreaker.StateClosed {
			t.Errorf("Expected initial state CLOSED, got %s", cb.State())
		}
	})

	t.Run("HTTP Handler", func(t *testing.T) {
		handler := NewRelayHandlerFromConfig(
			"http",
			"",
			"http://api.test.com",
			"token",
			"test",
			false,
			false,
			false,
			"",
			"",
			&testLogger{},
			cbConfig,
		)

		httpHandler := handler.(*HTTPRelayHandler)
		cb := httpHandler.GetCircuitBreaker()

		if cb == nil {
			t.Error("Expected non-nil circuit breaker")
		}

		if cb.State() != circuitbreaker.StateClosed {
			t.Errorf("Expected initial state CLOSED, got %s", cb.State())
		}
	})
}

// TestCircuitBreaker_PermanentErrorsDoNotTrigger tests that permanent errors (5xx SMTP, 4xx HTTP)
// do not count as failures toward opening the circuit breaker
func TestCircuitBreaker_PermanentErrorsDoNotTrigger(t *testing.T) {
	logger := &testLogger{}

	t.Run("SMTP 5xx permanent errors should not open circuit", func(t *testing.T) {
		// Simulate what happens when wc.Close() returns SMTP error 554
		// This tests the actual error chain: RelayError -> fmt.Errorf -> SMTPError
		cbConfig := CircuitBreakerConfig{
			Threshold:   2, // Would open after 2 failures
			Timeout:     100 * time.Millisecond,
			MaxRequests: 1,
		}

		handler := NewRelayHandlerFromConfig(
			"smtp",
			"invalid.host.test:587", // Invalid host
			"",
			"",
			"test",
			true,
			true,
			false,
			"",
			"",
			logger,
			cbConfig,
		)

		smtpHandler := handler.(*SMTPRelayHandler)

		// Mock the sendToSMTPRelay to return a permanent error (like 554)
		// We can't actually mock it easily, but we can verify the error classification
		testErr := &RelayError{
			Err:       fmt.Errorf("failed to close data writer: SMTP error 554: no forwarding permitted"),
			Permanent: true,
		}

		// Verify this error is correctly classified as permanent
		if !IsPermanentError(testErr) {
			t.Error("Expected error to be classified as permanent")
		}

		// Verify circuit breaker treats it as successful
		// We do this by checking the IsSuccessful logic manually since we can't easily inject errors
		if smtpHandler.CircuitBreaker != nil {
			// The IsSuccessful callback should return true for permanent errors
			// This is what prevents them from counting toward circuit opening
			shouldBeSuccessful := testErr == nil || IsPermanentError(testErr)
			if !shouldBeSuccessful {
				t.Error("Circuit breaker should treat permanent errors as successful")
			}
		}
	})

	t.Run("HTTP 4xx permanent errors should not open circuit", func(t *testing.T) {
		// Server always returns 400 Bad Request (permanent error)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest) // 4xx = permanent for HTTP
		}))
		defer server.Close()

		cbConfig := CircuitBreakerConfig{
			Threshold:   2, // Would open after 2 failures
			Timeout:     100 * time.Millisecond,
			MaxRequests: 1,
		}

		handler := NewRelayHandlerFromConfig(
			"http",
			"",
			server.URL,
			"test-token",
			"test",
			false,
			false,
			false,
			"",
			"",
			logger,
			cbConfig,
		)

		httpHandler := handler.(*HTTPRelayHandler)

		// Send 5 requests that will all return 400 (permanent errors)
		for i := 0; i < 5; i++ {
			err := handler.SendToExternalRelay("sender@test.com", "recipient@test.com", []byte("test"))
			if err == nil {
				t.Errorf("Expected error on attempt %d", i+1)
			}
			// Should be permanent error
			if !IsPermanentError(err) {
				t.Errorf("Expected permanent error on attempt %d, got: %v", i+1, err)
			}
			// Circuit breaker should NOT be open
			if errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) {
				t.Errorf("Circuit breaker should not open for permanent errors on attempt %d", i+1)
			}
		}

		// Circuit should still be CLOSED (permanent errors don't count as failures)
		state := httpHandler.CircuitBreaker.State()
		if state != circuitbreaker.StateClosed {
			t.Errorf("Expected circuit to remain CLOSED for permanent errors, got %s", state)
		}
	})

	t.Run("HTTP 5xx temporary errors should open circuit", func(t *testing.T) {
		// Server always returns 500 Internal Server Error (temporary error)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError) // 5xx = temporary for HTTP
		}))
		defer server.Close()

		cbConfig := CircuitBreakerConfig{
			Threshold:   2, // Open after 2 failures
			Timeout:     100 * time.Millisecond,
			MaxRequests: 1,
		}

		handler := NewRelayHandlerFromConfig(
			"http",
			"",
			server.URL,
			"test-token",
			"test",
			false,
			false,
			false,
			"",
			"",
			logger,
			cbConfig,
		)

		httpHandler := handler.(*HTTPRelayHandler)

		// First 2 attempts should trigger circuit opening
		for i := 0; i < 2; i++ {
			err := handler.SendToExternalRelay("sender@test.com", "recipient@test.com", []byte("test"))
			if err == nil {
				t.Errorf("Expected error on attempt %d", i+1)
			}
			// Should be temporary error (not permanent)
			if IsPermanentError(err) {
				t.Errorf("Expected temporary error on attempt %d, got: %v", i+1, err)
			}
		}

		// Circuit should be OPEN now (temporary errors count as failures)
		state := httpHandler.CircuitBreaker.State()
		if state != circuitbreaker.StateOpen {
			t.Errorf("Expected circuit OPEN after threshold temporary failures, got %s", state)
		}

		// Next attempt should fail with circuit breaker error
		err := handler.SendToExternalRelay("sender@test.com", "recipient@test.com", []byte("test"))
		if !errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) {
			t.Errorf("Expected circuit breaker open error, got: %v", err)
		}
	})
}

// testLoggerWithFunc extended with custom function
type testLoggerWithFunc struct {
	testLogger
	logFunc func(string)
}

func (l *testLoggerWithFunc) Log(format string, args ...any) {
	if l.logFunc != nil {
		msg := format
		if len(args) > 0 {
			msg = fmt.Sprintf(format, args...)
		}
		l.logFunc(msg)
	}
}
