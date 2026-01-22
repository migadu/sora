package delivery

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/emersion/go-smtp"
)

// Mock logger for testing
type testLogger struct {
	logs []string
}

func (l *testLogger) Log(format string, args ...any) {
	l.logs = append(l.logs, fmt.Sprintf(format, args...))
}

// TestNewRelayHandlerFromConfig tests the relay handler factory
func TestNewRelayHandlerFromConfig(t *testing.T) {
	logger := &testLogger{}

	tests := []struct {
		name                string
		relayType           string
		smtpHost            string
		httpURL             string
		httpToken           string
		metricsLabel        string
		useTLS              bool
		tlsVerify           bool
		useStartTLS         bool
		tlsCertFile         string
		tlsKeyFile          string
		expectedHandlerType string
		expectedNil         bool
	}{
		{
			name:                "SMTP relay handler",
			relayType:           "smtp",
			smtpHost:            "smtp.example.com:587",
			metricsLabel:        "test",
			useTLS:              true,
			tlsVerify:           true,
			useStartTLS:         true,
			expectedHandlerType: "*delivery.SMTPRelayHandler",
		},
		{
			name:                "HTTP relay handler",
			relayType:           "http",
			httpURL:             "https://api.example.com/deliver",
			httpToken:           "token123",
			metricsLabel:        "test",
			expectedHandlerType: "*delivery.HTTPRelayHandler",
		},
		{
			name:        "Invalid relay type",
			relayType:   "invalid",
			expectedNil: true,
		},
		{
			name:        "Empty relay type",
			relayType:   "",
			expectedNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewRelayHandlerFromConfig(
				tt.relayType,
				tt.smtpHost,
				tt.httpURL,
				tt.httpToken,
				tt.metricsLabel,
				tt.useTLS,
				tt.tlsVerify,
				tt.useStartTLS,
				tt.tlsCertFile,
				tt.tlsKeyFile,
				logger,
				CircuitBreakerConfig{}, // Use defaults
			)

			if tt.expectedNil {
				if handler != nil {
					t.Errorf("Expected nil handler, got %T", handler)
				}
				return
			}

			if handler == nil {
				t.Fatal("Expected non-nil handler")
			}

			handlerType := fmt.Sprintf("%T", handler)
			if handlerType != tt.expectedHandlerType {
				t.Errorf("Expected handler type %s, got %s", tt.expectedHandlerType, handlerType)
			}

			// Verify SMTP handler configuration
			if smtpHandler, ok := handler.(*SMTPRelayHandler); ok {
				if smtpHandler.SMTPHost != tt.smtpHost {
					t.Errorf("Expected SMTPHost %s, got %s", tt.smtpHost, smtpHandler.SMTPHost)
				}
				if smtpHandler.UseTLS != tt.useTLS {
					t.Errorf("Expected UseTLS %v, got %v", tt.useTLS, smtpHandler.UseTLS)
				}
				if smtpHandler.TLSVerify != tt.tlsVerify {
					t.Errorf("Expected TLSVerify %v, got %v", tt.tlsVerify, smtpHandler.TLSVerify)
				}
				if smtpHandler.UseStartTLS != tt.useStartTLS {
					t.Errorf("Expected UseStartTLS %v, got %v", tt.useStartTLS, smtpHandler.UseStartTLS)
				}
			}

			// Verify HTTP handler configuration
			if httpHandler, ok := handler.(*HTTPRelayHandler); ok {
				if httpHandler.HTTPURL != tt.httpURL {
					t.Errorf("Expected HTTPURL %s, got %s", tt.httpURL, httpHandler.HTTPURL)
				}
				if httpHandler.AuthToken != tt.httpToken {
					t.Errorf("Expected AuthToken %s, got %s", tt.httpToken, httpHandler.AuthToken)
				}
			}
		})
	}
}

// TestHTTPRelayHandler tests the HTTP relay handler
func TestHTTPRelayHandler(t *testing.T) {
	tests := []struct {
		name           string
		from           string
		to             string
		message        []byte
		token          string
		serverResponse int
		serverBody     string
		expectError    bool
		errorContains  string
	}{
		{
			name:           "Successful delivery",
			from:           "sender@example.com",
			to:             "recipient@example.com",
			message:        []byte("Subject: Test\r\n\r\nTest message"),
			token:          "valid-token",
			serverResponse: http.StatusOK,
			serverBody:     `{"status":"ok"}`,
			expectError:    false,
		},
		{
			name:           "Server error",
			from:           "sender@example.com",
			to:             "recipient@example.com",
			message:        []byte("Subject: Test\r\n\r\nTest message"),
			token:          "valid-token",
			serverResponse: http.StatusInternalServerError,
			serverBody:     `{"error":"internal error"}`,
			expectError:    true,
			errorContains:  "500",
		},
		{
			name:           "Unauthorized",
			from:           "sender@example.com",
			to:             "recipient@example.com",
			message:        []byte("Subject: Test\r\n\r\nTest message"),
			token:          "invalid-token",
			serverResponse: http.StatusUnauthorized,
			serverBody:     `{"error":"unauthorized"}`,
			expectError:    true,
			errorContains:  "401",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Verify method
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST method, got %s", r.Method)
				}

				// Verify authorization header
				authHeader := r.Header.Get("Authorization")
				expectedAuth := "Bearer " + tt.token
				if authHeader != expectedAuth {
					w.WriteHeader(http.StatusUnauthorized)
					w.Write([]byte(`{"error":"unauthorized"}`))
					return
				}

				// Verify content type
				contentType := r.Header.Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("Expected Content-Type application/json, got %s", contentType)
				}

				w.WriteHeader(tt.serverResponse)
				w.Write([]byte(tt.serverBody))
			}))
			defer server.Close()

			logger := &testLogger{}
			handler := &HTTPRelayHandler{
				HTTPURL:      server.URL,
				AuthToken:    tt.token,
				MetricsLabel: "test",
				Logger:       logger,
			}

			err := handler.SendToExternalRelay(tt.from, tt.to, tt.message)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.errorContains != "" && !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("Expected error containing %q, got %q", tt.errorContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

// TestHTTPRelayHandlerInvalidURL tests HTTP relay with invalid URL
func TestHTTPRelayHandlerInvalidURL(t *testing.T) {
	logger := &testLogger{}
	handler := &HTTPRelayHandler{
		HTTPURL:      "http://invalid-host-that-does-not-exist-12345.example:99999",
		AuthToken:    "token",
		MetricsLabel: "test",
		Logger:       logger,
	}

	err := handler.SendToExternalRelay("from@example.com", "to@example.com", []byte("test"))
	if err == nil {
		t.Error("Expected error for invalid URL, got nil")
	}
}

// TestSMTPRelayHandlerConfiguration tests SMTP handler configuration
func TestSMTPRelayHandlerConfiguration(t *testing.T) {
	tests := []struct {
		name           string
		useTLS         bool
		tlsVerify      bool
		useStartTLS    bool
		tlsCertFile    string
		tlsKeyFile     string
		expectedConfig func(*testing.T, *SMTPRelayHandler)
	}{
		{
			name:        "Direct TLS enabled",
			useTLS:      true,
			tlsVerify:   true,
			useStartTLS: false,
			expectedConfig: func(t *testing.T, h *SMTPRelayHandler) {
				if !h.UseTLS {
					t.Error("Expected UseTLS to be true")
				}
				if !h.TLSVerify {
					t.Error("Expected TLSVerify to be true")
				}
				if h.UseStartTLS {
					t.Error("Expected UseStartTLS to be false")
				}
			},
		},
		{
			name:        "STARTTLS enabled",
			useTLS:      true,
			tlsVerify:   true,
			useStartTLS: true,
			expectedConfig: func(t *testing.T, h *SMTPRelayHandler) {
				if !h.UseTLS {
					t.Error("Expected UseTLS to be true")
				}
				if !h.UseStartTLS {
					t.Error("Expected UseStartTLS to be true")
				}
			},
		},
		{
			name:        "TLS disabled",
			useTLS:      false,
			tlsVerify:   false,
			useStartTLS: false,
			expectedConfig: func(t *testing.T, h *SMTPRelayHandler) {
				if h.UseTLS {
					t.Error("Expected UseTLS to be false")
				}
			},
		},
		{
			name:        "TLS with client cert",
			useTLS:      true,
			tlsVerify:   true,
			useStartTLS: false,
			tlsCertFile: "/path/to/cert.crt",
			tlsKeyFile:  "/path/to/key.key",
			expectedConfig: func(t *testing.T, h *SMTPRelayHandler) {
				if h.TLSCertFile != "/path/to/cert.crt" {
					t.Errorf("Expected TLSCertFile to be /path/to/cert.crt, got %s", h.TLSCertFile)
				}
				if h.TLSKeyFile != "/path/to/key.key" {
					t.Errorf("Expected TLSKeyFile to be /path/to/key.key, got %s", h.TLSKeyFile)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := &testLogger{}
			handler := &SMTPRelayHandler{
				SMTPHost:     "smtp.example.com:587",
				UseTLS:       tt.useTLS,
				TLSVerify:    tt.tlsVerify,
				UseStartTLS:  tt.useStartTLS,
				TLSCertFile:  tt.tlsCertFile,
				TLSKeyFile:   tt.tlsKeyFile,
				MetricsLabel: "test",
				Logger:       logger,
			}

			tt.expectedConfig(t, handler)
		})
	}
}

// Benchmark tests
func BenchmarkNewRelayHandlerFromConfig(b *testing.B) {
	logger := &testLogger{}

	b.Run("SMTP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			NewRelayHandlerFromConfig(
				"smtp",
				"smtp.example.com:587",
				"",
				"",
				"test",
				true,
				true,
				true,
				"",
				"",
				logger,
				CircuitBreakerConfig{},
			)
		}
	})

	b.Run("HTTP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			NewRelayHandlerFromConfig(
				"http",
				"",
				"https://api.example.com/deliver",
				"token",
				"test",
				false,
				false,
				false,
				"",
				"",
				logger,
				CircuitBreakerConfig{},
			)
		}
	})
}

func BenchmarkHTTPRelayHandler(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	logger := &testLogger{}
	handler := &HTTPRelayHandler{
		HTTPURL:      server.URL,
		AuthToken:    "token",
		MetricsLabel: "test",
		Logger:       logger,
	}

	message := []byte("Subject: Test\r\n\r\nTest message body")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		handler.SendToExternalRelay("from@example.com", "to@example.com", message)
	}
}

// TestIsPermanentError tests the error classification logic
func TestIsPermanentError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantPerm bool
	}{
		{
			name:     "nil error",
			err:      nil,
			wantPerm: false,
		},
		{
			name:     "generic error (temporary)",
			err:      errors.New("generic error"),
			wantPerm: false,
		},
		{
			name:     "SMTP 4xx error (temporary)",
			err:      &smtp.SMTPError{Code: 421, Message: "Service not available"},
			wantPerm: false,
		},
		{
			name:     "SMTP 450 mailbox busy (temporary)",
			err:      &smtp.SMTPError{Code: 450, Message: "Requested mail action not taken: mailbox unavailable"},
			wantPerm: false,
		},
		{
			name:     "SMTP 451 local error (temporary)",
			err:      &smtp.SMTPError{Code: 451, Message: "Requested action aborted: local error in processing"},
			wantPerm: false,
		},
		{
			name:     "SMTP 452 insufficient storage (temporary)",
			err:      &smtp.SMTPError{Code: 452, Message: "Requested action not taken: insufficient system storage"},
			wantPerm: false,
		},
		{
			name:     "SMTP 5xx error (permanent)",
			err:      &smtp.SMTPError{Code: 550, Message: "Requested action not taken: mailbox unavailable"},
			wantPerm: true,
		},
		{
			name:     "SMTP 551 user not local (permanent)",
			err:      &smtp.SMTPError{Code: 551, Message: "User not local; please try <forward-path>"},
			wantPerm: true,
		},
		{
			name:     "SMTP 552 exceeded storage (permanent)",
			err:      &smtp.SMTPError{Code: 552, Message: "Requested mail action aborted: exceeded storage allocation"},
			wantPerm: true,
		},
		{
			name:     "SMTP 553 mailbox name invalid (permanent)",
			err:      &smtp.SMTPError{Code: 553, Message: "Requested action not taken: mailbox name not allowed"},
			wantPerm: true,
		},
		{
			name:     "SMTP 554 transaction failed (permanent)",
			err:      &smtp.SMTPError{Code: 554, Message: "Transaction failed"},
			wantPerm: true,
		},
		{
			name:     "wrapped SMTP 4xx (temporary)",
			err:      fmt.Errorf("context: %w", &smtp.SMTPError{Code: 450, Message: "mailbox busy"}),
			wantPerm: false,
		},
		{
			name:     "wrapped SMTP 5xx (permanent)",
			err:      fmt.Errorf("context: %w", &smtp.SMTPError{Code: 550, Message: "mailbox not found"}),
			wantPerm: true,
		},
		{
			name:     "RelayError temporary",
			err:      &RelayError{Err: errors.New("temp"), Permanent: false},
			wantPerm: false,
		},
		{
			name:     "RelayError permanent",
			err:      &RelayError{Err: errors.New("perm"), Permanent: true},
			wantPerm: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsPermanentError(tt.err)
			if got != tt.wantPerm {
				t.Errorf("IsPermanentError() = %v, want %v", got, tt.wantPerm)
			}
		})
	}
}

// TestRelayError tests the RelayError wrapper
func TestRelayError(t *testing.T) {
	tests := []struct {
		name     string
		err      *RelayError
		wantMsg  string
		wantPerm bool
	}{
		{
			name:     "temporary error",
			err:      &RelayError{Err: errors.New("network timeout"), Permanent: false},
			wantMsg:  "temporary failure: network timeout",
			wantPerm: false,
		},
		{
			name:     "permanent error",
			err:      &RelayError{Err: errors.New("mailbox not found"), Permanent: true},
			wantMsg:  "permanent failure: mailbox not found",
			wantPerm: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantMsg {
				t.Errorf("RelayError.Error() = %v, want %v", got, tt.wantMsg)
			}
			if got := IsPermanentError(tt.err); got != tt.wantPerm {
				t.Errorf("IsPermanentError(RelayError) = %v, want %v", got, tt.wantPerm)
			}
		})
	}
}

// TestRelayError_Unwrap tests error unwrapping
func TestRelayError_Unwrap(t *testing.T) {
	innerErr := errors.New("inner error")
	relayErr := &RelayError{Err: innerErr, Permanent: true}

	if !errors.Is(relayErr, innerErr) {
		t.Errorf("errors.Is() should find inner error")
	}

	if unwrapped := relayErr.Unwrap(); unwrapped != innerErr {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, innerErr)
	}
}

// TestHTTPRelayHandler_ErrorClassification tests HTTP error classification
func TestHTTPRelayHandler_ErrorClassification(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		expectError    bool
		expectPermanent bool
	}{
		{
			name:            "200 OK - success",
			statusCode:      http.StatusOK,
			expectError:     false,
			expectPermanent: false,
		},
		{
			name:            "400 Bad Request - permanent",
			statusCode:      http.StatusBadRequest,
			expectError:     true,
			expectPermanent: true,
		},
		{
			name:            "401 Unauthorized - permanent",
			statusCode:      http.StatusUnauthorized,
			expectError:     true,
			expectPermanent: true,
		},
		{
			name:            "404 Not Found - permanent",
			statusCode:      http.StatusNotFound,
			expectError:     true,
			expectPermanent: true,
		},
		{
			name:            "500 Internal Server Error - temporary",
			statusCode:      http.StatusInternalServerError,
			expectError:     true,
			expectPermanent: false,
		},
		{
			name:            "502 Bad Gateway - temporary",
			statusCode:      http.StatusBadGateway,
			expectError:     true,
			expectPermanent: false,
		},
		{
			name:            "503 Service Unavailable - temporary",
			statusCode:      http.StatusServiceUnavailable,
			expectError:     true,
			expectPermanent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			handler := &HTTPRelayHandler{
				HTTPURL:      server.URL,
				AuthToken:    "token",
				MetricsLabel: "test",
			}

			err := handler.SendToExternalRelay("from@example.com", "to@example.com", []byte("test"))

			if tt.expectError {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}

				isPerm := IsPermanentError(err)
				if isPerm != tt.expectPermanent {
					t.Errorf("IsPermanentError() = %v, want %v for status %d", isPerm, tt.expectPermanent, tt.statusCode)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}
