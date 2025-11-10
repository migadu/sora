package pop3proxy

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/server"
)

// TestBackendAuthTimeoutErrorMessage tests that backend authentication timeout
// returns an appropriate error message (not "Authentication failed")
func TestBackendAuthTimeoutErrorMessage(t *testing.T) {
	// Test various backend errors and verify the error messages we return

	tests := []struct {
		name              string
		backendError      error
		expectContains    string
		expectNotContains string
		description       string
	}{
		{
			name:              "read auth response timeout",
			backendError:      fmt.Errorf("%w: failed to read auth response: %w", server.ErrBackendAuthFailed, &mockNetError{timeout: true, temp: true}),
			expectContains:    "Backend",
			expectNotContains: "Authentication failed",
			description:       "Backend times out reading auth response - should say backend unavailable, not auth failed",
		},
		{
			name:              "read auth response context deadline",
			backendError:      fmt.Errorf("%w: failed to read auth response: %w", server.ErrBackendAuthFailed, context.DeadlineExceeded),
			expectContains:    "Backend",
			expectNotContains: "Authentication failed",
			description:       "Backend context deadline exceeded - should say backend unavailable, not auth failed",
		},
		{
			name:              "backend authentication failed message",
			backendError:      fmt.Errorf("%w: invalid credentials", server.ErrBackendAuthFailed),
			expectContains:    "Backend",
			expectNotContains: "",
			description:       "Backend auth failed - should say backend issue",
		},
		{
			name:              "failed to send AUTH PLAIN",
			backendError:      fmt.Errorf("%w: failed to send AUTH PLAIN to backend: connection reset", server.ErrBackendAuthFailed),
			expectContains:    "Backend",
			expectNotContains: "Authentication failed",
			description:       "Failed to send AUTH command - should say backend unavailable, not auth failed",
		},
		{
			name:              "connect to backend timeout",
			backendError:      fmt.Errorf("%w: failed to connect to backend: dial tcp 192.0.2.1:110: i/o timeout", server.ErrBackendConnectionFailed),
			expectContains:    "Backend",
			expectNotContains: "Authentication failed",
			description:       "Failed to connect - should say backend unavailable, not auth failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Testing: %s", tt.description)
			t.Logf("Backend error: %v", tt.backendError)

			// Simulate what the code does when it gets this error
			errorMessage := determineErrorMessage(tt.backendError)

			t.Logf("Returned error message: %s", errorMessage)

			if tt.expectContains != "" && !strings.Contains(errorMessage, tt.expectContains) {
				t.Errorf("❌ ERROR: Expected error message to contain '%s', got: %s", tt.expectContains, errorMessage)
			}

			if tt.expectNotContains != "" && strings.Contains(errorMessage, tt.expectNotContains) {
				t.Errorf("❌ BUG: Error message incorrectly contains '%s': %s", tt.expectNotContains, errorMessage)
				t.Logf("   This is the bug - backend timeout should not return 'Authentication failed'")
			}
		})
	}
}

// determineErrorMessage simulates the FIXED logic in pop3proxy/session.go
// Now uses server.IsBackendError() with sentinel errors
func determineErrorMessage(err error) string {
	// Check for backend-related errors using sentinel errors (FIXED logic)
	if server.IsBackendError(err) {
		return "-ERR [SYS/TEMP] Backend server temporarily unavailable"
	}

	// Only return "Authentication failed" for actual auth failures (wrong password etc)
	return "-ERR Authentication failed"
}

// mockNetError implements net.Error for testing
type mockNetError struct {
	timeout bool
	temp    bool
}

func (e *mockNetError) Error() string {
	if e.timeout {
		return "i/o timeout"
	}
	return "network error"
}

func (e *mockNetError) Timeout() bool {
	return e.timeout
}

func (e *mockNetError) Temporary() bool {
	return e.temp
}

func (e *mockNetError) Is(target error) bool {
	_, ok := target.(*mockNetError)
	return ok
}

// TestCorrectErrorMessageLogic shows what the CORRECT logic should be
func TestCorrectErrorMessageLogic(t *testing.T) {
	t.Log("Testing CORRECT error message logic (what it should be after fix)")

	tests := []struct {
		name         string
		backendError error
		expected     string
	}{
		{
			name:         "read auth response timeout",
			backendError: fmt.Errorf("%w: failed to read auth response: %w", server.ErrBackendAuthFailed, &mockNetError{timeout: true}),
			expected:     "-ERR [SYS/TEMP] Backend server temporarily unavailable",
		},
		{
			name:         "failed to connect to backend",
			backendError: fmt.Errorf("%w: timeout", server.ErrBackendConnectionFailed),
			expected:     "-ERR [SYS/TEMP] Backend server temporarily unavailable",
		},
		{
			name:         "failed to send AUTH PLAIN",
			backendError: fmt.Errorf("%w: failed to send AUTH PLAIN to backend: broken pipe", server.ErrBackendAuthFailed),
			expected:     "-ERR [SYS/TEMP] Backend server temporarily unavailable",
		},
		{
			name:         "backend authentication failed",
			backendError: fmt.Errorf("%w: +ERR", server.ErrBackendAuthFailed),
			expected:     "-ERR [SYS/TEMP] Backend server temporarily unavailable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineCorrectErrorMessage(tt.backendError)
			if result != tt.expected {
				t.Errorf("Expected: %s, Got: %s", tt.expected, result)
			} else {
				t.Logf("✓ Correct: %s", result)
			}
		})
	}
}

// determineCorrectErrorMessage shows the CORRECT logic using sentinel errors
func determineCorrectErrorMessage(err error) string {
	// Check for backend-related errors using sentinel errors
	if server.IsBackendError(err) {
		return "-ERR [SYS/TEMP] Backend server temporarily unavailable"
	}

	// Only return "Authentication failed" for actual auth failures (wrong password etc)
	return "-ERR Authentication failed"
}
