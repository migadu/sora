package delivery

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Mock logger for testing
type testLogger struct {
	logs []string
}

func (l *testLogger) Log(format string, args ...interface{}) {
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
