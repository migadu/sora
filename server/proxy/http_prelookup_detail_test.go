package proxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestHTTPPrelookupDetailStripping verifies that +detail is stripped correctly
// and master tokens are preserved when making prelookup HTTP requests
func TestHTTPPrelookupDetailStripping(t *testing.T) {
	tests := []struct {
		name             string
		inputEmail       string
		expectedURLEmail string // What should be in the URL
		description      string
	}{
		{
			name:             "simple_email",
			inputEmail:       "user@example.com",
			expectedURLEmail: "user@example.com",
			description:      "Simple email without +detail or master token",
		},
		{
			name:             "email_with_detail",
			inputEmail:       "user+tag@example.com",
			expectedURLEmail: "user@example.com",
			description:      "+detail should be stripped from URL",
		},
		{
			name:             "email_with_master_token",
			inputEmail:       "user@example.com@TOKEN",
			expectedURLEmail: "user@example.com@TOKEN", // Case preserved for security
			description:      "Master token preserved with original case",
		},
		{
			name:             "email_with_detail_and_master_token",
			inputEmail:       "user+tag@example.com@TOKEN",
			expectedURLEmail: "user@example.com@TOKEN", // Case preserved for security
			description:      "+detail stripped, master token case preserved",
		},
		{
			name:             "complex_detail",
			inputEmail:       "user+important.tag@example.com",
			expectedURLEmail: "user@example.com",
			description:      "Complex +detail with dots should be stripped",
		},
		{
			name:             "complex_detail_with_token",
			inputEmail:       "user+important.tag@example.com@MyToken123",
			expectedURLEmail: "user@example.com@MyToken123", // Case preserved for security
			description:      "Complex +detail stripped, token case preserved",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Track what email was actually sent in the HTTP request
			var capturedEmail string

			// Create test server that captures the email from URL
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Extract email from query parameter
				emailParam := r.URL.Query().Get("email")
				capturedEmail = emailParam

				// Return valid response
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"address":       "user@example.com",
					"password_hash": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
					"server":        "backend:143",
				})
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
				nil,   // circuit breaker settings
				nil,   // transport settings
			)

			// Perform lookup
			ctx := context.Background()
			_, _, err := client.LookupUserRoute(ctx, tt.inputEmail, "testpassword")

			// We expect authentication to fail (wrong password), but request should be made
			if err != nil {
				t.Errorf("Unexpected error (should only fail auth, not request): %v", err)
			}

			// Verify the email sent in URL matches expected
			if capturedEmail != tt.expectedURLEmail {
				t.Errorf("%s: Expected URL email '%s', got '%s'", tt.description, tt.expectedURLEmail, capturedEmail)
			} else {
				t.Logf("✓ %s: Correctly sent '%s' in URL (input was '%s')", tt.description, capturedEmail, tt.inputEmail)
			}
		})
	}
}

// TestHTTPPrelookupURLEncoding verifies that emails are properly URL-encoded
func TestHTTPPrelookupURLEncoding(t *testing.T) {
	tests := []struct {
		name          string
		inputEmail    string
		expectedParam string // Expected URL-decoded parameter value
		description   string
	}{
		{
			name:          "special_chars_in_local",
			inputEmail:    "user.name+tag@example.com",
			expectedParam: "user.name@example.com",
			description:   "Dots and +detail in local part",
		},
		{
			name:          "at_symbol_in_token",
			inputEmail:    "user@example.com@TOKEN",
			expectedParam: "user@example.com@TOKEN", // Case preserved for security
			description:   "@ symbol in master token should be encoded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedRawURL string

			// Create test server that captures raw URL
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				capturedRawURL = r.URL.RawQuery

				// Return valid response
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{
					"address":       "user@example.com",
					"password_hash": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
					"server":        "backend:143",
				})
			}))
			defer server.Close()

			client := NewHTTPPreLookupClient(
				server.URL+"/lookup?email=$email",
				5*time.Second,
				"test-token",
				143,
				false, false, false, false, false, false,
				nil, nil, nil,
			)

			ctx := context.Background()
			client.LookupUserRoute(ctx, tt.inputEmail, "testpassword")

			// Parse the captured query string
			values, err := url.ParseQuery(capturedRawURL)
			if err != nil {
				t.Fatalf("Failed to parse query string: %v", err)
			}

			capturedEmail := values.Get("email")
			if capturedEmail != tt.expectedParam {
				t.Errorf("%s: Expected '%s', got '%s'", tt.description, tt.expectedParam, capturedEmail)
			} else {
				t.Logf("✓ %s: Correctly encoded and sent '%s'", tt.description, capturedEmail)
			}
		})
	}
}
