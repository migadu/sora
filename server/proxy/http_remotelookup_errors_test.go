package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/circuitbreaker"
)

// TestHTTPRemoteLookupErrorTypes verifies that the HTTP remotelookup client returns
// the correct error types for different failure scenarios
func TestHTTPRemoteLookupErrorTypes(t *testing.T) {
	tests := []struct {
		name             string
		handler          http.HandlerFunc
		expectAuthResult AuthResult
		expectErrorType  error // ErrRemoteLookupTransient, ErrRemoteLookupInvalidResponse, or nil
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
			expectAuthResult: AuthTemporarilyUnavailable,
			expectErrorType:  ErrRemoteLookupTransient,
			description:      "4xx errors (except 401/403/404) say nothing about the credentials: service unavailable, as the lookup contract documents",
		},
		{
			name: "408_RequestTimeout",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error": "request timeout"}`, http.StatusRequestTimeout)
			},
			expectAuthResult: AuthTemporarilyUnavailable,
			expectErrorType:  ErrRemoteLookupTransient,
			description:      "408 (RFC 9110 section 15.5.9) is the lookup service timing out, not a wrong password",
		},
		{
			name: "429_TooManyRequests",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error": "slow down"}`, http.StatusTooManyRequests)
			},
			expectAuthResult: AuthTemporarilyUnavailable,
			expectErrorType:  ErrRemoteLookupTransient,
			description:      "429 (RFC 6585 section 4) is the lookup service rate-limiting this proxy, not a wrong password",
		},
		{
			name: "422_UnprocessableContent",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error": "unprocessable"}`, http.StatusUnprocessableEntity)
			},
			expectAuthResult: AuthTemporarilyUnavailable,
			expectErrorType:  ErrRemoteLookupTransient,
			description:      "4xx errors (except 401/403/404) say nothing about the credentials: service unavailable, as the lookup contract documents",
		},
		{
			name: "500_ServerError",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
			},
			expectAuthResult: AuthTemporarilyUnavailable,
			expectErrorType:  ErrRemoteLookupTransient,
			description:      "5xx errors should return AuthTemporarilyUnavailable with ErrRemoteLookupTransient",
		},
		{
			name: "503_ServiceUnavailable",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, `{"error": "service unavailable"}`, http.StatusServiceUnavailable)
			},
			expectAuthResult: AuthTemporarilyUnavailable,
			expectErrorType:  ErrRemoteLookupTransient,
			description:      "503 should return AuthTemporarilyUnavailable with ErrRemoteLookupTransient",
		},
		{
			name: "200_InvalidJSON",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("this is not json"))
			},
			expectAuthResult: AuthTemporarilyUnavailable,
			expectErrorType:  ErrRemoteLookupInvalidResponse,
			description:      "200 with invalid JSON (e.g. a maintenance page) is a broken lookup service: temporary, ErrRemoteLookupInvalidResponse",
		},
		{
			name: "200_MissingAddress",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"password_hash": "$2a$10$abcdefghijklmnopqrstuvwxyz",
					"server":        "backend:143",
					// address is missing (required)
				})
			},
			expectAuthResult: AuthTemporarilyUnavailable,
			expectErrorType:  ErrRemoteLookupInvalidResponse,
			description:      "200 with missing address should return ErrRemoteLookupInvalidResponse",
		},
		{
			name: "200_EmptyAddress",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"address":       "",
					"password_hash": "$2a$10$abcdefghijklmnopqrstuvwxyz",
					"server":        "backend:143",
				})
			},
			expectAuthResult: AuthTemporarilyUnavailable,
			expectErrorType:  ErrRemoteLookupInvalidResponse,
			description:      "200 with empty address should return ErrRemoteLookupInvalidResponse",
		},
		{
			name: "200_MissingHashedPassword",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"address": "user@example.com",
					"server":  "backend:143",
					// password_hash is missing
				})
			},
			expectAuthResult: AuthTemporarilyUnavailable,
			expectErrorType:  ErrRemoteLookupInvalidResponse,
			description:      "200 with missing password_hash should return ErrRemoteLookupInvalidResponse",
		},
		{
			name: "200_EmptyHashedPassword",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"address":       "user@example.com",
					"password_hash": "",
					"server":        "backend:143",
				})
			},
			expectAuthResult: AuthTemporarilyUnavailable,
			expectErrorType:  ErrRemoteLookupInvalidResponse,
			description:      "200 with empty password_hash should return ErrRemoteLookupInvalidResponse",
		},
		{
			name: "200_UnverifiableHashedPassword",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"address":       "user@example.com",
					"password_hash": "{SHA512-CRYPT}$6$saltsaltsaltsalt$Uz0B733KLAcpeAFT5hlALRwUMzwqxSoBO9VG7Ph8v7auZDaXL8PutBQPqOVLMvwy0rORlpwlXHm83Z4uAhgLB0",
					"server":        "backend:143",
				})
			},
			expectAuthResult: AuthTemporarilyUnavailable,
			expectErrorType:  ErrRemoteLookupInvalidResponse,
			description:      "200 with a password_hash sora cannot verify says nothing about the password: an invalid answer, not a wrong password",
		},
		{
			name: "200_MissingServerIP_AuthOnlyMode",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"address":       "user@example.com",
					"password_hash": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", // bcrypt hash of "password"
					// server is missing - auth-only mode (remotelookup authenticates, Sora routes)
				})
			},
			expectAuthResult: AuthFailed, // Password verification will fail (testpassword != password)
			expectErrorType:  nil,
			description:      "200 with missing server triggers auth-only mode (password verification still happens)",
		},
		{
			name: "200_ValidResponse",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
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

			// Create remotelookup client
			client := NewHTTPRemoteLookupClient(
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
				false, // remoteUseUTF8
				nil,   // circuit breaker settings (use defaults)
				nil,   // transport settings (use defaults)
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
			}
			// The proxies branch on the error, not on the result: a temporary answer
			// without ErrRemoteLookupTransient is handled by the session as something else.
			if tt.expectAuthResult == AuthTemporarilyUnavailable && !errors.Is(err, ErrRemoteLookupTransient) {
				t.Errorf("%s: temporary answer without ErrRemoteLookupTransient: %v", tt.description, err)
			}
			if tt.expectErrorType == nil && tt.expectAuthResult == AuthUserNotFound {
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

// TestHTTPRemoteLookupNetworkError verifies that network errors return ErrRemoteLookupTransient
func TestHTTPRemoteLookupNetworkError(t *testing.T) {
	// Create remotelookup client pointing to non-existent server
	client := NewHTTPRemoteLookupClient(
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
		false, // remoteUseUTF8
		nil,   // circuit breaker settings (use defaults)
		nil,   // transport settings (use defaults)
	)

	// Perform lookup
	ctx := context.Background()
	_, authResult, err := client.LookupUserRoute(ctx, "test@example.com", "testpassword")

	// Should return AuthTemporarilyUnavailable with ErrRemoteLookupTransient
	if authResult != AuthTemporarilyUnavailable {
		t.Errorf("Expected AuthTemporarilyUnavailable for network error, got %v", authResult)
	}

	if err == nil {
		t.Fatal("Expected error for network failure, got nil")
	}

	if !errors.Is(err, ErrRemoteLookupTransient) {
		t.Errorf("Expected ErrRemoteLookupTransient for network error, got: %v", err)
	}

	t.Logf("✓ Network error correctly returns AuthTemporarilyUnavailable with ErrRemoteLookupTransient: %v", err)
}

// TestHTTPRemoteLookupUnbuildableRequestIsUnavailable (#518): a lookup whose request
// cannot be built gives no verdict on the user either. With $email in the host the
// escaped address ("user%40example.com") is not a valid host, so every request fails
// before it is sent. That was AuthFailed with an error the proxies did not classify,
// and they fell back to the database. The startup check now rejects such a URL (#655);
// this client is built without it.
func TestHTTPRemoteLookupUnbuildableRequestIsUnavailable(t *testing.T) {
	client := NewHTTPRemoteLookupClient(
		"https://$email.lookup.example.com/lookup",
		time.Second,
		"",
		143,
		false, // remoteTLS
		false, // remoteTLSUseStartTLS
		false, // remoteTLSVerify
		false, // remoteUseProxyProtocol
		false, // remoteUseIDCommand
		false, // remoteUseXCLIENT
		false, // remoteUseUTF8
		nil,   // circuit breaker settings (use defaults)
		nil,   // transport settings (use defaults)
	)

	_, authResult, err := client.LookupUserRoute(context.Background(), "user@example.com", "secret")
	if authResult != AuthTemporarilyUnavailable || !errors.Is(err, ErrRemoteLookupTransient) {
		t.Fatalf("lookup with a request that cannot be built: %v, %v; want %v with ErrRemoteLookupTransient", authResult, err, AuthTemporarilyUnavailable)
	}
}

// TestHTTPRemoteLookupCircuitBreaker verifies that circuit breaker open returns ErrRemoteLookupTransient
func TestHTTPRemoteLookupCircuitBreaker(t *testing.T) {
	// Create a server that always fails
	failCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failCount++
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}))
	defer server.Close()

	// Create remotelookup client
	client := NewHTTPRemoteLookupClient(
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
		false, // remoteUseUTF8
		nil,   // circuit breaker settings (use defaults)
		nil,   // transport settings (use defaults)
	)

	ctx := context.Background()

	// Make multiple requests to trigger circuit breaker
	// Circuit breaker opens after 60% of 5 requests fail
	for i := 0; i < 10; i++ {
		_, authResult, err := client.LookupUserRoute(ctx, "test@example.com", "testpassword")

		// All should return AuthTemporarilyUnavailable (service errors are transient)
		if authResult != AuthTemporarilyUnavailable {
			t.Errorf("Request %d: Expected AuthTemporarilyUnavailable, got %v", i+1, authResult)
		}

		// All should have an error with ErrRemoteLookupTransient
		if err == nil {
			t.Errorf("Request %d: Expected error, got nil", i+1)
		} else if !errors.Is(err, ErrRemoteLookupTransient) {
			t.Errorf("Request %d: Expected ErrRemoteLookupTransient, got: %v", i+1, err)
		}

		// After enough failures, circuit breaker should open
		if i >= 5 && client.breaker.State().String() == "open" {
			t.Logf("✓ Circuit breaker opened after %d requests", i+1)
			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	// Verify final error is still ErrRemoteLookupTransient with AuthTemporarilyUnavailable
	_, authResult, err := client.LookupUserRoute(ctx, "test@example.com", "testpassword")
	if authResult != AuthTemporarilyUnavailable {
		t.Errorf("Final request: Expected AuthTemporarilyUnavailable, got %v", authResult)
	}
	if !errors.Is(err, ErrRemoteLookupTransient) {
		t.Errorf("Final request: Expected ErrRemoteLookupTransient even with circuit breaker open, got: %v", err)
	}

	t.Logf("✓ Circuit breaker correctly returns AuthTemporarilyUnavailable with ErrRemoteLookupTransient when open")
	t.Logf("  Total requests made: %d, Circuit breaker state: %s", failCount, client.breaker.State())
}

// TestHTTPRemoteLookupCircuitBreakerHalfOpen: once the open timeout has passed, the breaker
// lets exactly MaxRequests lookups through to the service at a time and refuses the rest
// as temporarily unavailable (ErrTooManyRequests wrapped as ErrRemoteLookupTransient). A
// successful probe closes it; a failed probe opens it again at once, so the next lookup is
// refused without reaching the service.
func TestHTTPRemoteLookupCircuitBreakerHalfOpen(t *testing.T) {
	const (
		maxRequests = 3
		openTimeout = 300 * time.Millisecond
	)
	var (
		failing atomic.Bool // answer 500 instead of holding and answering 200
		hits    atomic.Int32
		arrived = make(chan struct{}, 16)
		release = make(chan struct{})
	)
	failing.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if failing.Load() {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		arrived <- struct{}{}
		<-release
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"address":       "user@example.com",
			"password_hash": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
			"server":        "backend:143",
		})
	}))
	defer server.Close()
	var releaseOnce sync.Once
	releaseProbes := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseProbes() // before server.Close, which waits for held handlers

	// The default settings with a short open timeout.
	client := NewHTTPRemoteLookupClient(
		server.URL+"/lookup?email=$email",
		30*time.Second, // outlasts the test's own waits, so a held probe never times out

		"test-token",
		143,
		false, // remoteTLS
		false, // remoteTLSUseStartTLS
		false, // remoteTLSVerify
		false, // remoteUseProxyProtocol
		false, // remoteUseIDCommand
		false, // remoteUseXCLIENT
		false, // remoteUseUTF8
		&CircuitBreakerSettings{MaxRequests: maxRequests, Timeout: openTimeout, FailureRatio: 0.6, MinRequests: 3},
		nil, // transport settings (use defaults)
	)
	ctx := context.Background()
	lookup := func() error {
		_, _, err := client.LookupUserRouteWithOptions(ctx, "user@example.com", "", true)
		return err
	}
	// openBreaker fails lookups until the breaker opens, then waits out the open timeout.
	openBreaker := func(phase string) {
		t.Helper()
		failing.Store(true)
		for i := 0; client.breaker.State() != circuitbreaker.StateOpen; i++ {
			if i == 10 {
				t.Fatalf("%s: breaker still %s after %d failed lookups", phase, client.breaker.State(), i)
			}
			lookup()
		}
		before := hits.Load()
		if err := lookup(); !errors.Is(err, ErrRemoteLookupTransient) {
			t.Fatalf("%s: lookup with the breaker open: got %v, want ErrRemoteLookupTransient", phase, err)
		}
		if hits.Load() != before {
			t.Fatalf("%s: a lookup reached the service while the breaker was open", phase)
		}
		deadline := time.Now().Add(openTimeout + 2*time.Second)
		for client.breaker.State() != circuitbreaker.StateHalfOpen {
			if time.Now().After(deadline) {
				t.Fatalf("%s: breaker still %s %v after it opened (open timeout %v)", phase, client.breaker.State(), openTimeout+2*time.Second, openTimeout)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	// Half-open admits exactly maxRequests concurrent probes; the others are refused.
	openBreaker("first outage")
	failing.Store(false)
	hitsBefore := hits.Load()
	const extra = 2
	results := make(chan error, maxRequests+extra)
	for i := 0; i < maxRequests+extra; i++ {
		go func() { results <- lookup() }()
	}
	for i := 0; i < extra; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, ErrRemoteLookupTransient) {
				t.Fatalf("lookup beyond the %d half-open probes: got %v, want ErrRemoteLookupTransient", maxRequests, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d lookups beyond the half-open probes were refused", i, extra)
		}
	}
	for i := 0; i < maxRequests; i++ {
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatalf("%d of %d half-open probes reached the service", i, maxRequests)
		}
	}
	if n := hits.Load() - hitsBefore; n != maxRequests {
		t.Fatalf("%d half-open probes reached the service, want %d", n, maxRequests)
	}
	releaseProbes()
	for i := 0; i < maxRequests; i++ {
		if err := <-results; err != nil {
			t.Fatalf("half-open probe %d: %v", i+1, err)
		}
	}
	if s := client.breaker.State(); s != circuitbreaker.StateClosed {
		t.Fatalf("breaker %s after successful half-open probes, want CLOSED", s)
	}

	// A failed half-open probe opens the breaker again at once.
	openBreaker("second outage")
	if err := lookup(); !errors.Is(err, ErrRemoteLookupTransient) {
		t.Fatalf("failed half-open probe: got %v, want ErrRemoteLookupTransient", err)
	}
	if s := client.breaker.State(); s != circuitbreaker.StateOpen {
		t.Fatalf("breaker %s after a failed half-open probe, want OPEN", s)
	}
	before := hits.Load()
	if err := lookup(); !errors.Is(err, ErrRemoteLookupTransient) || hits.Load() != before {
		t.Fatalf("lookup after a failed half-open probe: got %v and %d service hits, want ErrRemoteLookupTransient and none", err, hits.Load()-before)
	}
}

// TestHTTPRemoteLookupInvalidEmail verifies that invalid email addresses are rejected early
// without making HTTP requests
func TestHTTPRemoteLookupInvalidEmail(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"address":       "user@example.com",
			"password_hash": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
			"server":        "backend:143",
		})
	}))
	defer server.Close()

	client := NewHTTPRemoteLookupClient(
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
		false, // remoteUseUTF8
		nil,   // circuit breaker settings (use defaults)
		nil,   // transport settings (use defaults)
	)

	invalidCases := []struct {
		email       string
		description string
	}{
		{"bennai+yamina", "username without domain"},
		{"user", "username without @ symbol"},
		{"", "empty string"},
		{"   ", "whitespace only"},
		{"user @example.com", "space before domain"},
		{"user@ example.com", "space after @"},
		{"user @example.com", "space before and after @"},
		{"user@exam ple.com", "space in domain"},
		{"us er@example.com", "space in local part"},
		{"user\t@example.com", "internal tab character"},
		{"user@exam\nple.com", "internal newline character"},
	}

	ctx := context.Background()

	// Test invalid emails - should be rejected without HTTP request
	for _, tc := range invalidCases {
		t.Run(tc.description, func(t *testing.T) {
			initialCount := requestCount
			routingInfo, authResult, err := client.LookupUserRoute(ctx, tc.email, "testpassword")

			// Should return AuthFailed (not AuthUserNotFound) to prevent fallback to database auth
			if authResult != AuthFailed {
				t.Errorf("Expected AuthFailed for '%s', got %v", tc.email, authResult)
			}

			if routingInfo != nil {
				t.Errorf("Expected nil routing info for invalid email '%s', got %+v", tc.email, routingInfo)
			}

			if err != nil {
				t.Errorf("Expected no error for invalid email '%s', got %v", tc.email, err)
			}

			if requestCount != initialCount {
				t.Errorf("HTTP request was made for invalid email '%s' (request count: %d -> %d)", tc.email, initialCount, requestCount)
			}

			t.Logf("✓ Invalid email '%s' rejected with AuthFailed (no HTTP request, no DB fallback)", tc.email)
		})
	}

	// Test emails with leading/trailing whitespace - should be trimmed and make HTTP request
	trimCases := []struct {
		email       string
		description string
	}{
		{"  user@example.com  ", "leading and trailing spaces"},
		{" user@example.com", "leading space"},
		{"user@example.com ", "trailing space"},
		{"\tuser@example.com\t", "leading and trailing tabs"},
		{"user@example.com\n", "trailing newline"},
		{"\nuser@example.com", "leading newline"},
	}

	for _, tc := range trimCases {
		t.Run("trim_"+tc.description, func(t *testing.T) {
			initialCount := requestCount
			client.LookupUserRoute(ctx, tc.email, "testpassword")

			if requestCount == initialCount {
				t.Errorf("Email '%s' should have been trimmed and made HTTP request", tc.email)
			} else {
				t.Logf("✓ Email '%s' trimmed correctly and made HTTP request", tc.email)
			}
		})
	}

	// Verify valid email DOES make a request
	initialCount := requestCount
	client.LookupUserRoute(ctx, "user@example.com", "testpassword")
	if requestCount == initialCount {
		t.Error("Valid email should have made HTTP request")
	} else {
		t.Logf("✓ Valid email made HTTP request as expected")
	}

	// Verify master token format (multiple @) is allowed and makes HTTP request
	initialCount = requestCount
	routingInfo, authResult, err := client.LookupUserRoute(ctx, "user@example.com@TOKEN", "testpassword")
	if authResult == AuthFailed && routingInfo == nil && err == nil && requestCount == initialCount {
		t.Error("Master token format should not be rejected as invalid (should make HTTP request)")
	} else if requestCount == initialCount {
		t.Error("Master token format should have made HTTP request")
	} else {
		t.Logf("✓ Master token format (user@example.com@TOKEN) allowed and made HTTP request")
	}

	// Verify +detail addressing is stripped before making HTTP request
	t.Run("plus_addressing_stripped", func(t *testing.T) {
		client := NewHTTPRemoteLookupClient(
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
			false, // remoteUseUTF8
			nil,   // circuit breaker settings (use defaults)
			nil,   // transport settings (use defaults)
		)

		// Test that user+tag@example.com sends user@example.com to HTTP endpoint
		initialCount := requestCount
		client.LookupUserRoute(ctx, "user+tag@example.com", "testpassword")

		if requestCount == initialCount {
			t.Error("Should have made HTTP request for +detail address")
		} else {
			t.Logf("✓ Email with +detail (user+tag@example.com) made HTTP request")
		}

		// Test that user+tag@example.com@TOKEN sends user@example.com@TOKEN (strip +tag, keep @TOKEN)
		initialCount = requestCount
		client.LookupUserRoute(ctx, "user+tag@example.com@TOKEN", "testpassword")

		if requestCount == initialCount {
			t.Error("Should have made HTTP request for +detail address with master token")
		} else {
			t.Logf("✓ Email with +detail and master token (user+tag@example.com@TOKEN) made HTTP request")
		}
	})
}
