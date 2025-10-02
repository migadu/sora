package managesieve

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/migadu/sora/server"
)

func TestAuthenticationParameterQuoting(t *testing.T) {
	tests := []struct {
		name           string
		commandLine    string
		wantMechanism  string
		wantAuthData   string
		wantParseError bool
	}{
		{
			name:          "AUTHENTICATE with quoted mechanism and inline response",
			commandLine:   `AUTHENTICATE "PLAIN" "dGVzdEB0ZXN0LmNvbQB0ZXN0"`,
			wantMechanism: "PLAIN",
			wantAuthData:  "dGVzdEB0ZXN0LmNvbQB0ZXN0",
		},
		{
			name:          "AUTHENTICATE with unquoted mechanism and inline response",
			commandLine:   "AUTHENTICATE PLAIN dGVzdEB0ZXN0LmNvbQB0ZXN0",
			wantMechanism: "PLAIN",
			wantAuthData:  "dGVzdEB0ZXN0LmNvbQB0ZXN0",
		},
		{
			name:          "AUTHENTICATE with quoted mechanism only",
			commandLine:   `AUTHENTICATE "PLAIN"`,
			wantMechanism: "PLAIN",
			wantAuthData:  "",
		},
		{
			name:          "AUTHENTICATE with unquoted mechanism only",
			commandLine:   "AUTHENTICATE PLAIN",
			wantMechanism: "PLAIN",
			wantAuthData:  "",
		},
		{
			name:          "AUTHENTICATE with lowercase mechanism",
			commandLine:   "AUTHENTICATE plain dGVzdEB0ZXN0LmNvbQB0ZXN0",
			wantMechanism: "PLAIN",
			wantAuthData:  "dGVzdEB0ZXN0LmNvbQB0ZXN0",
		},
		{
			name:          "AUTHENTICATE with quoted lowercase mechanism",
			commandLine:   `AUTHENTICATE "plain" "dGVzdEB0ZXN0LmNvbQB0ZXN0"`,
			wantMechanism: "PLAIN",
			wantAuthData:  "dGVzdEB0ZXN0LmNvbQB0ZXN0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the command line the same way the session does
			parts := strings.SplitN(tt.commandLine, " ", 3)
			if len(parts) < 2 {
				if !tt.wantParseError {
					t.Errorf("Failed to parse command: not enough parts")
				}
				return
			}

			// Extract mechanism with quote handling (same as in handleAuthenticate)
			mechanism := server.UnquoteString(parts[1])
			mechanism = strings.ToUpper(mechanism)

			if mechanism != tt.wantMechanism {
				t.Errorf("Mechanism = %q, want %q", mechanism, tt.wantMechanism)
			}

			// Check inline auth data if present
			if len(parts) > 2 {
				authData := server.UnquoteString(parts[2])
				if authData != tt.wantAuthData {
					t.Errorf("AuthData = %q, want %q", authData, tt.wantAuthData)
				}
			} else if tt.wantAuthData != "" {
				t.Errorf("No auth data found, want %q", tt.wantAuthData)
			}
		})
	}
}

func TestLoginParameterQuoting(t *testing.T) {
	tests := []struct {
		name         string
		commandLine  string
		wantAddress  string
		wantPassword string
	}{
		{
			name:         "LOGIN with quoted parameters",
			commandLine:  `LOGIN "user@example.com" "password123"`,
			wantAddress:  "user@example.com",
			wantPassword: "password123",
		},
		{
			name:         "LOGIN with unquoted parameters",
			commandLine:  "LOGIN user@example.com password123",
			wantAddress:  "user@example.com",
			wantPassword: "password123",
		},
		{
			name:         "LOGIN with mixed quoting",
			commandLine:  `LOGIN "user@example.com" password123`,
			wantAddress:  "user@example.com",
			wantPassword: "password123",
		},
		{
			name:         "LOGIN with special characters in password",
			commandLine:  `LOGIN "user@example.com" "p@ssw0rd!#$"`,
			wantAddress:  "user@example.com",
			wantPassword: "p@ssw0rd!#$",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the command line the same way the session does
			parts := strings.SplitN(tt.commandLine, " ", 3)
			if len(parts) < 3 {
				t.Fatalf("Failed to parse command: not enough parts")
			}

			// Extract parameters with quote handling (same as in LOGIN handler)
			userAddress := server.UnquoteString(parts[1])
			password := server.UnquoteString(parts[2])

			if userAddress != tt.wantAddress {
				t.Errorf("UserAddress = %q, want %q", userAddress, tt.wantAddress)
			}
			if password != tt.wantPassword {
				t.Errorf("Password = %q, want %q", password, tt.wantPassword)
			}
		})
	}
}

func TestSASLPlainEncoding(t *testing.T) {
	tests := []struct {
		name     string
		authzID  string
		authnID  string
		password string
	}{
		{
			name:     "Standard SASL PLAIN",
			authzID:  "",
			authnID:  "user@example.com",
			password: "password123",
		},
		{
			name:     "SASL PLAIN with authorization identity",
			authzID:  "admin@example.com",
			authnID:  "user@example.com",
			password: "password123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create SASL PLAIN string: authzID \0 authnID \0 password
			saslPlain := tt.authzID + "\x00" + tt.authnID + "\x00" + tt.password
			encoded := base64.StdEncoding.EncodeToString([]byte(saslPlain))

			// Decode it back
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				t.Fatalf("Failed to decode base64: %v", err)
			}

			// Parse SASL PLAIN format
			parts := strings.Split(string(decoded), "\x00")
			if len(parts) != 3 {
				t.Fatalf("Invalid SASL PLAIN format: got %d parts, want 3", len(parts))
			}

			if parts[0] != tt.authzID {
				t.Errorf("AuthzID = %q, want %q", parts[0], tt.authzID)
			}
			if parts[1] != tt.authnID {
				t.Errorf("AuthnID = %q, want %q", parts[1], tt.authnID)
			}
			if parts[2] != tt.password {
				t.Errorf("Password = %q, want %q", parts[2], tt.password)
			}
		})
	}
}

func TestContinuationResponseQuoting(t *testing.T) {
	tests := []struct {
		name         string
		response     string
		wantAuthData string
	}{
		{
			name:         "Quoted continuation response",
			response:     `"dGVzdEB0ZXN0LmNvbQB0ZXN0"`,
			wantAuthData: "dGVzdEB0ZXN0LmNvbQB0ZXN0",
		},
		{
			name:         "Unquoted continuation response",
			response:     "dGVzdEB0ZXN0LmNvbQB0ZXN0",
			wantAuthData: "dGVzdEB0ZXN0LmNvbQB0ZXN0",
		},
		{
			name:         "Continuation response with whitespace",
			response:     "  dGVzdEB0ZXN0LmNvbQB0ZXN0  ",
			wantAuthData: "dGVzdEB0ZXN0LmNvbQB0ZXN0",
		},
		{
			name:         "Quoted continuation response with whitespace",
			response:     `  "dGVzdEB0ZXN0LmNvbQB0ZXN0"  `,
			wantAuthData: "dGVzdEB0ZXN0LmNvbQB0ZXN0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate continuation response processing
			authData := strings.TrimSpace(tt.response)
			authData = server.UnquoteString(authData)

			if authData != tt.wantAuthData {
				t.Errorf("AuthData = %q, want %q", authData, tt.wantAuthData)
			}
		})
	}
}
