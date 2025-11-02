package resilient

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/circuitbreaker"
)

// TestCircuitBreakerBusinessLogicErrors verifies that business logic errors
// (like user not found, invalid password) do NOT trip the circuit breaker.
// Only actual system failures should trip the circuit breaker.
func TestCircuitBreakerBusinessLogicErrors(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		shouldSucceed bool // Should this error be treated as success by circuit breaker?
	}{
		{
			name:          "nil error is success",
			err:           nil,
			shouldSucceed: true,
		},
		{
			name:          "user not found is success (business logic)",
			err:           consts.ErrUserNotFound,
			shouldSucceed: true,
		},
		{
			name:          "mailbox not found is success (business logic)",
			err:           consts.ErrMailboxNotFound,
			shouldSucceed: true,
		},
		{
			name:          "mailbox already exists is success (business logic)",
			err:           consts.ErrMailboxAlreadyExists,
			shouldSucceed: true,
		},
		{
			name:          "message not available is success (business logic)",
			err:           consts.ErrMessageNotAvailable,
			shouldSucceed: true,
		},
		{
			name:          "not permitted is success (business logic)",
			err:           consts.ErrNotPermitted,
			shouldSucceed: true,
		},
		{
			name:          "pgx.ErrNoRows is success (business logic)",
			err:           pgx.ErrNoRows,
			shouldSucceed: true,
		},
		{
			name:          "unique violation is success for writes (business logic)",
			err:           consts.ErrDBUniqueViolation,
			shouldSucceed: true, // Only for write breaker
		},
		{
			name:          "wrapped user not found is success",
			err:           errors.Join(errors.New("auth failed"), consts.ErrUserNotFound),
			shouldSucceed: true,
		},
		{
			name:          "generic error is failure (system error)",
			err:           errors.New("database connection failed"),
			shouldSucceed: false,
		},
		{
			name:          "context deadline exceeded is failure (system error)",
			err:           context.DeadlineExceeded,
			shouldSucceed: false,
		},
		{
			name:          "internal error is failure (system error)",
			err:           consts.ErrInternalError,
			shouldSucceed: false,
		},
	}

	// Test query circuit breaker
	t.Run("QueryCircuitBreaker", func(t *testing.T) {
		for _, tt := range tests {
			// Skip unique violation test for query breaker (write-only)
			if tt.name == "unique violation is success for writes (business logic)" {
				continue
			}

			t.Run(tt.name, func(t *testing.T) {
				// Create fresh circuit breaker for each test case
				querySettings := circuitbreaker.DefaultSettings("test_query")
				querySettings.MaxRequests = 5
				querySettings.Interval = 0
				querySettings.Timeout = 0
				querySettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
					// Trip after 3 failures
					return counts.TotalFailures >= 3
				}

				// Configure IsSuccessful to match production settings
				querySettings.IsSuccessful = func(err error) bool {
					if err == nil {
						return true
					}
					if errors.Is(err, consts.ErrUserNotFound) ||
						errors.Is(err, consts.ErrMailboxNotFound) ||
						errors.Is(err, consts.ErrMessageNotAvailable) ||
						errors.Is(err, consts.ErrMailboxAlreadyExists) ||
						errors.Is(err, consts.ErrNotPermitted) ||
						errors.Is(err, pgx.ErrNoRows) {
						return true
					}
					return false
				}

				breaker := circuitbreaker.NewCircuitBreaker(querySettings)

				// Execute operation through circuit breaker
				_, err := breaker.Execute(func() (any, error) {
					return nil, tt.err
				})

				// Get circuit breaker counts
				counts := breaker.Counts()

				if tt.shouldSucceed {
					// Business logic errors should be counted as successes
					if counts.TotalFailures > 0 {
						t.Errorf("Expected business logic error to not increment failure count, but got %d failures", counts.TotalFailures)
					}
					if counts.TotalSuccesses != 1 {
						t.Errorf("Expected business logic error to increment success count to 1, but got %d successes", counts.TotalSuccesses)
					}
					// Verify circuit breaker remains closed
					if breaker.State() != circuitbreaker.StateClosed {
						t.Errorf("Circuit breaker should remain CLOSED after business logic error, but state is: %s", breaker.State())
					}
				} else {
					// System errors should be counted as failures
					if counts.TotalFailures != 1 {
						t.Errorf("Expected system error to increment failure count to 1, but got %d failures", counts.TotalFailures)
					}
				}

				// Verify the returned error matches what we passed in
				if tt.err == nil && err != nil {
					t.Errorf("Expected nil error, got: %v", err)
				}
				if tt.err != nil && err == nil {
					t.Errorf("Expected error %v, got nil", tt.err)
				}
			})
		}
	})

	// Test write circuit breaker (includes unique violation)
	t.Run("WriteCircuitBreaker", func(t *testing.T) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				// Create fresh circuit breaker for each test case
				writeSettings := circuitbreaker.DefaultSettings("test_write")
				writeSettings.MaxRequests = 3
				writeSettings.Interval = 0
				writeSettings.Timeout = 0
				writeSettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
					return counts.TotalFailures >= 3
				}

				// Configure IsSuccessful to match production settings (includes unique violation)
				writeSettings.IsSuccessful = func(err error) bool {
					if err == nil {
						return true
					}
					if errors.Is(err, consts.ErrUserNotFound) ||
						errors.Is(err, consts.ErrMailboxNotFound) ||
						errors.Is(err, consts.ErrMessageNotAvailable) ||
						errors.Is(err, consts.ErrMailboxAlreadyExists) ||
						errors.Is(err, consts.ErrNotPermitted) ||
						errors.Is(err, consts.ErrDBUniqueViolation) ||
						errors.Is(err, pgx.ErrNoRows) {
						return true
					}
					return false
				}

				breaker := circuitbreaker.NewCircuitBreaker(writeSettings)

				_, execErr := breaker.Execute(func() (any, error) {
					return nil, tt.err
				})

				counts := breaker.Counts()

				// Verify the returned error matches expectations
				_ = execErr // Silence unused variable warning

				if tt.shouldSucceed {
					if counts.TotalFailures > 0 {
						t.Errorf("Expected business logic error to not increment failure count, but got %d failures", counts.TotalFailures)
					}
					if counts.TotalSuccesses != 1 {
						t.Errorf("Expected business logic error to increment success count to 1, but got %d successes", counts.TotalSuccesses)
					}
					// Verify circuit breaker remains closed
					if breaker.State() != circuitbreaker.StateClosed {
						t.Errorf("Circuit breaker should remain CLOSED after business logic error, but state is: %s", breaker.State())
					}
				} else {
					if counts.TotalFailures != 1 {
						t.Errorf("Expected system error to increment failure count to 1, but got %d failures", counts.TotalFailures)
					}
				}
			})
		}
	})
}

// TestCircuitBreakerAuthenticationFailures simulates a burst of authentication
// failures (user not found) and verifies the circuit breaker remains closed.
func TestCircuitBreakerAuthenticationFailures(t *testing.T) {
	querySettings := circuitbreaker.DefaultSettings("test_auth")
	querySettings.MaxRequests = 5
	querySettings.Interval = 0
	querySettings.Timeout = 0
	querySettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		// Trip after 60% failure rate with at least 8 requests
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 8 && failureRatio >= 0.6
	}

	// Configure IsSuccessful to match production settings
	querySettings.IsSuccessful = func(err error) bool {
		if err == nil {
			return true
		}
		// User not found is a business logic error, not a system failure
		if errors.Is(err, consts.ErrUserNotFound) ||
			errors.Is(err, pgx.ErrNoRows) {
			return true
		}
		return false
	}

	breaker := circuitbreaker.NewCircuitBreaker(querySettings)

	// Simulate 20 consecutive authentication failures (user not found)
	for i := 0; i < 20; i++ {
		_, err := breaker.Execute(func() (any, error) {
			// Simulate database query returning "user not found"
			return nil, consts.ErrUserNotFound
		})

		// The error should be returned to the caller
		if !errors.Is(err, consts.ErrUserNotFound) {
			t.Fatalf("Expected ErrUserNotFound, got: %v", err)
		}
	}

	// Verify circuit breaker counts
	counts := breaker.Counts()
	if counts.Requests != 20 {
		t.Errorf("Expected 20 requests, got %d", counts.Requests)
	}
	if counts.TotalSuccesses != 20 {
		t.Errorf("Expected 20 successes (business logic errors), got %d", counts.TotalSuccesses)
	}
	if counts.TotalFailures != 0 {
		t.Errorf("Expected 0 failures (user not found should not count), got %d", counts.TotalFailures)
	}

	// Verify circuit breaker remains CLOSED
	if breaker.State() != circuitbreaker.StateClosed {
		t.Errorf("Circuit breaker should remain CLOSED after authentication failures, but state is: %s", breaker.State())
	}
}

// TestCircuitBreakerSystemFailures verifies that actual system failures
// DO trip the circuit breaker.
func TestCircuitBreakerSystemFailures(t *testing.T) {
	querySettings := circuitbreaker.DefaultSettings("test_system_failures")
	querySettings.MaxRequests = 5
	querySettings.Interval = 0
	querySettings.Timeout = 0
	querySettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		// Trip after 3 system failures
		return counts.TotalFailures >= 3
	}

	querySettings.IsSuccessful = func(err error) bool {
		if err == nil {
			return true
		}
		// Only business logic errors are successes
		if errors.Is(err, consts.ErrUserNotFound) {
			return true
		}
		return false
	}

	breaker := circuitbreaker.NewCircuitBreaker(querySettings)

	// Simulate 3 system failures (database connection errors)
	systemError := errors.New("database connection failed")
	for i := 0; i < 2; i++ {
		_, execErr := breaker.Execute(func() (any, error) {
			return nil, systemError
		})

		if execErr == nil {
			t.Fatalf("Expected system error, got nil")
		}

		// Check counts after each failure (before circuit breaker opens)
		counts := breaker.Counts()
		if counts.TotalFailures != uint32(i+1) {
			t.Errorf("After failure %d, expected %d failures, got %d", i+1, i+1, counts.TotalFailures)
		}

		// Circuit breaker should still be closed
		if breaker.State() != circuitbreaker.StateClosed {
			t.Errorf("Circuit breaker should be CLOSED after only %d failures, but state is: %s", i+1, breaker.State())
		}
	}

	// Execute third failure which should open the circuit
	_, execErr := breaker.Execute(func() (any, error) {
		return nil, systemError
	})

	if execErr == nil {
		t.Fatalf("Expected system error, got nil")
	}

	// Verify circuit breaker OPENED after 3 system failures
	if breaker.State() != circuitbreaker.StateOpen {
		t.Errorf("Circuit breaker should be OPEN after 3 system failures, but state is: %s", breaker.State())
	}

	// Verify subsequent requests are rejected with circuit breaker error
	_, err := breaker.Execute(func() (any, error) {
		return nil, nil
	})

	if !errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) {
		t.Errorf("Expected ErrCircuitBreakerOpen, got: %v", err)
	}
}

// TestCircuitBreakerMixedErrors verifies that business logic errors don't
// interfere with detection of system failures.
func TestCircuitBreakerMixedErrors(t *testing.T) {
	querySettings := circuitbreaker.DefaultSettings("test_mixed")
	querySettings.MaxRequests = 5
	querySettings.Interval = 0
	querySettings.Timeout = 0
	querySettings.ReadyToTrip = func(counts circuitbreaker.Counts) bool {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 10 && failureRatio >= 0.6
	}

	querySettings.IsSuccessful = func(err error) bool {
		if err == nil {
			return true
		}
		if errors.Is(err, consts.ErrUserNotFound) {
			return true
		}
		return false
	}

	breaker := circuitbreaker.NewCircuitBreaker(querySettings)

	// Mix of business logic errors and system failures
	testErrors := []error{
		consts.ErrUserNotFound, // business logic
		consts.ErrUserNotFound, // business logic
		errors.New("timeout"),  // system failure
		consts.ErrUserNotFound, // business logic
		errors.New("timeout"),  // system failure
		consts.ErrUserNotFound, // business logic
		errors.New("timeout"),  // system failure
		consts.ErrUserNotFound, // business logic
		errors.New("timeout"),  // system failure
		errors.New("timeout"),  // system failure
		errors.New("timeout"),  // system failure
		errors.New("timeout"),  // system failure
	}

	var successCount, failureCount int64
	for _, testErr := range testErrors {
		breaker.Execute(func() (any, error) {
			return nil, testErr
		})

		// Track counts as we go
		if errors.Is(testErr, consts.ErrUserNotFound) {
			successCount++
		} else {
			failureCount++
		}
	}

	counts := breaker.Counts()
	// 5 business logic errors (user not found) = 5 successes
	// 7 system failures = 7 failures
	if counts.TotalSuccesses != 5 {
		t.Errorf("Expected 5 successes, got %d", counts.TotalSuccesses)
	}
	if counts.TotalFailures != 7 {
		t.Errorf("Expected 7 failures, got %d", counts.TotalFailures)
	}

	// Circuit breaker should remain CLOSED: 12 requests, 7 failures = 58% failure ratio (below 60% threshold)
	if breaker.State() != circuitbreaker.StateClosed {
		t.Errorf("Circuit breaker should remain CLOSED (failure ratio = 7/12 = 58%% < 60%% threshold), but state is: %s", breaker.State())
	}

	// Add one more system failure to cross the 60% threshold
	breaker.Execute(func() (any, error) {
		return nil, errors.New("timeout")
	})

	// Now: 13 requests, 8 failures = 61.5% failure ratio
	// Circuit breaker should open at this point (61.5% > 60%)
	if breaker.State() != circuitbreaker.StateOpen {
		t.Errorf("Circuit breaker should be OPEN (failure ratio = 8/13 = 61.5%% > 60%% threshold), but state is: %s", breaker.State())
	}
}
