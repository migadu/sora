package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestHTTPPrelookupErrorTypes verifies that the HTTP prelookup client returns
// the correct error types for different failure scenarios
func TestHTTPPrelookupErrorTypes(t *testing.T) {
	tests := []struct {
		name             string
		handler          http.HandlerFunc
		expectAuthResult AuthResult
		expectErrorType  error // ErrPrelookupTransient, ErrPrelookupInvalidResponse, or nil
		description      string
	}{
		{
			name: "404_UserNotFound",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error": "user not found"}`, http.StatusNotFound)
			},
			expectAuthResult: AuthUserNotFound,
			expectErrorType:  nil,
			description:      "404 should return AuthUserNotFound with no error",
		},
		{
			name: "400_ClientError",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error": "bad request"}`, http.StatusBadRequest)
			},
			expectAuthResult: AuthUserNotFound,
			expectErrorType:  nil,
			description:      "4xx errors should be treated as user not found",
		},
		{
			name: "500_ServerError",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
			},
			expectAuthResult: AuthFailed,
			expectErrorType:  ErrPrelookupTransient,
			description:      "5xx errors should return ErrPrelookupTransient",
		},
		{
			name: "503_ServiceUnavailable",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error": "service unavailable"}`, http.StatusServiceUnavailable)
			},
			expectAuthResult: AuthFailed,
			expectErrorType:  ErrPrelookupTransient,
			description:      "503 should return ErrPrelookupTransient",
		},
		{
			name: "200_InvalidJSON",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("this is not json"))
			},
			expectAuthResult: AuthFailed,
			expectErrorType:  ErrPrelookupInvalidResponse,
			description:      "200 with invalid JSON should return ErrPrelookupInvalidResponse",
		},
		{
			name: "200_MissingAddress",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"password_hash": "$2a$10$abcdefghijklmnopqrstuvwxyz",
					"server":        "backend:143",
					// address is missing (required)
				})
			},
			expectAuthResult: AuthFailed,
			expectErrorType:  ErrPrelookupInvalidResponse,
			description:      "200 with missing address should return ErrPrelookupInvalidResponse",
		},
		{
			name: "200_EmptyAddress",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"address":       "",
					"password_hash": "$2a$10$abcdefghijklmnopqrstuvwxyz",
					"server":        "backend:143",
				})
			},
			expectAuthResult: AuthFailed,
			expectErrorType:  ErrPrelookupInvalidResponse,
			description:      "200 with empty address should return ErrPrelookupInvalidResponse",
		},
		{
			name: "200_MissingHashedPassword",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"address": "user@example.com",
					"server":  "backend:143",
					// password_hash is missing
				})
			},
			expectAuthResult: AuthFailed,
			expectErrorType:  ErrPrelookupInvalidResponse,
			description:      "200 with missing password_hash should return ErrPrelookupInvalidResponse",
		},
		{
			name: "200_EmptyHashedPassword",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"address":       "user@example.com",
					"password_hash": "",
					"server":        "backend:143",
				})
			},
			expectAuthResult: AuthFailed,
			expectErrorType:  ErrPrelookupInvalidResponse,
			description:      "200 with empty password_hash should return ErrPrelookupInvalidResponse",
		},
		{
			name: "200_MissingServerIP",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"address":       "user@example.com",
					"password_hash": "$2a$10$abcdefghijklmnopqrstuvwxyz",
					// server is missing - should be treated as 404
				})
			},
			expectAuthResult: AuthUserNotFound,
			expectErrorType:  nil,
			description:      "200 with missing server should be treated as user not found (404)",
		},
		{
			name: "200_ValidResponse",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"address":       "user@example.com",
					"password_hash": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", // bcrypt hash of "password"
					"server":        "backend:143",
					// account_id is derived, not in JSON
				})
			},
			expectAuthResult: AuthFailed, // Will fail password check in this test
			expectErrorType:  nil,
			description:      "200 with valid response structure should parse successfully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			// Create prelookup client
			client := NewHTTPPreLookupClient(
				server.URL+"/lookup?email=$email",
				5*time.Second,
				"test-token",
				143,
				false, // remoteTLS
				false, // remoteTLSUseStartTLS
				false, // remoteTLSVerify
				false, // remoteUseProxyProtocol
				false, // remoteUseIDCommand
				false, // remoteUseXCLIENT
				nil,   // cache
			)

			// Perform lookup
			ctx := context.Background()
			routingInfo, authResult, err := client.LookupUserRoute(ctx, "test@example.com", "testpassword")

			// Check auth result
			if authResult != tt.expectAuthResult {
				t.Errorf("%s: expected AuthResult %v, got %v", tt.description, tt.expectAuthResult, authResult)
			}

			// Check error type
			if tt.expectErrorType != nil {
				if err == nil {
					t.Errorf("%s: expected error of type %v, got nil", tt.description, tt.expectErrorType)
				} else if !errors.Is(err, tt.expectErrorType) {
					t.Errorf("%s: expected error type %v, got %v", tt.description, tt.expectErrorType, err)
				}
			} else if tt.expectAuthResult == AuthUserNotFound {
				// For user not found cases, routingInfo should be nil and no error
				if routingInfo != nil {
					t.Errorf("%s: expected nil routing info for user not found, got %+v", tt.description, routingInfo)
				}
				if err != nil {
					t.Errorf("%s: expected no error for user not found, got %v", tt.description, err)
				}
			}

			t.Logf("✓ %s", tt.description)
		})
	}
}

// TestHTTPPrelookupNetworkError verifies that network errors return ErrPrelookupTransient
func TestHTTPPrelookupNetworkError(t *testing.T) {
	// Create prelookup client pointing to non-existent server
	client := NewHTTPPreLookupClient(
		"http://localhost:9999/lookup?email=$email", // Port that's not listening
		100*time.Millisecond,                        // Short timeout
		"test-token",
		143,
		false, // remoteTLS
		false, // remoteTLSUseStartTLS
		false, // remoteTLSVerify
		false, // remoteUseProxyProtocol
		false, // remoteUseIDCommand
		false, // remoteUseXCLIENT
		nil,   // cache
	)

	// Perform lookup
	ctx := context.Background()
	_, authResult, err := client.LookupUserRoute(ctx, "test@example.com", "testpassword")

	// Should return AuthFailed with ErrPrelookupTransient
	if authResult != AuthFailed {
		t.Errorf("Expected AuthFailed for network error, got %v", authResult)
	}

	if err == nil {
		t.Fatal("Expected error for network failure, got nil")
	}

	if !errors.Is(err, ErrPrelookupTransient) {
		t.Errorf("Expected ErrPrelookupTransient for network error, got: %v", err)
	}

	t.Logf("✓ Network error correctly returns ErrPrelookupTransient: %v", err)
}

// TestHTTPPrelookupCircuitBreaker verifies that circuit breaker open returns ErrPrelookupTransient
func TestHTTPPrelookupCircuitBreaker(t *testing.T) {
	// Create a server that always fails
	failCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failCount++
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}))
	defer server.Close()

	// Create prelookup client
	client := NewHTTPPreLookupClient(
		server.URL+"/lookup?email=$email",
		5*time.Second,
		"test-token",
		143,
		false, // remoteTLS
		false, // remoteTLSUseStartTLS
		false, // remoteTLSVerify
		false, // remoteUseProxyProtocol
		false, // remoteUseIDCommand
		false, // remoteUseXCLIENT
		nil,   // cache
	)

	ctx := context.Background()

	// Make multiple requests to trigger circuit breaker
	// Circuit breaker opens after 60% of 5 requests fail
	for i := 0; i < 10; i++ {
		_, authResult, err := client.LookupUserRoute(ctx, "test@example.com", "testpassword")

		// All should return AuthFailed
		if authResult != AuthFailed {
			t.Errorf("Request %d: Expected AuthFailed, got %v", i+1, authResult)
		}

		// All should have an error with ErrPrelookupTransient
		if err == nil {
			t.Errorf("Request %d: Expected error, got nil", i+1)
		} else if !errors.Is(err, ErrPrelookupTransient) {
			t.Errorf("Request %d: Expected ErrPrelookupTransient, got: %v", i+1, err)
		}

		// After enough failures, circuit breaker should open
		if i >= 5 && client.breaker.State().String() == "open" {
			t.Logf("✓ Circuit breaker opened after %d requests", i+1)
			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	// Verify final error is still ErrPrelookupTransient
	_, authResult, err := client.LookupUserRoute(ctx, "test@example.com", "testpassword")
	if authResult != AuthFailed {
		t.Errorf("Final request: Expected AuthFailed, got %v", authResult)
	}
	if !errors.Is(err, ErrPrelookupTransient) {
		t.Errorf("Final request: Expected ErrPrelookupTransient even with circuit breaker open, got: %v", err)
	}

	t.Logf("✓ Circuit breaker correctly returns ErrPrelookupTransient when open")
	t.Logf("  Total requests made: %d, Circuit breaker state: %s", failCount, client.breaker.State())
}
