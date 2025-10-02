package pop3

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/migadu/sora/server"
)

func TestUserCommandQuoting(t *testing.T) {
	tests := []struct {
		name         string
		commandLine  string
		wantUsername string
	}{
		{
			name:         "USER with quoted username",
			commandLine:  `USER "user@example.com"`,
			wantUsername: "user@example.com",
		},
		{
			name:         "USER with unquoted username",
			commandLine:  "USER user@example.com",
			wantUsername: "user@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the command line the same way POP3 session does
			parts := strings.Split(tt.commandLine, " ")
			if len(parts) < 2 {
				t.Fatalf("Failed to parse command: not enough parts")
			}

			// Extract username with quote handling
			username := server.UnquoteString(parts[1])

			if username != tt.wantUsername {
				t.Errorf("Username = %q, want %q", username, tt.wantUsername)
			}
		})
	}
}

func TestPassCommandQuoting(t *testing.T) {
	tests := []struct {
		name         string
		commandLine  string
		wantPassword string
	}{
		{
			name:         "PASS with quoted password",
			commandLine:  `PASS "password123"`,
			wantPassword: "password123",
		},
		{
			name:         "PASS with unquoted password",
			commandLine:  "PASS password123",
			wantPassword: "password123",
		},
		{
			name:         "PASS with special characters",
			commandLine:  `PASS "p@ssw0rd!#$"`,
			wantPassword: "p@ssw0rd!#$",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the command line the same way POP3 session does
			parts := strings.Split(tt.commandLine, " ")
			if len(parts) < 2 {
				t.Fatalf("Failed to parse command: not enough parts")
			}

			// Extract password with quote handling
			password := server.UnquoteString(parts[1])

			if password != tt.wantPassword {
				t.Errorf("Password = %q, want %q", password, tt.wantPassword)
			}
		})
	}
}

func TestAuthPlainQuoting(t *testing.T) {
	tests := []struct {
		name          string
		commandLine   string
		wantMechanism string
		wantAuthData  string
	}{
		{
			name:          "AUTH with quoted mechanism and inline response",
			commandLine:   `AUTH "PLAIN" "dGVzdEB0ZXN0LmNvbQB0ZXN0"`,
			wantMechanism: "PLAIN",
			wantAuthData:  "dGVzdEB0ZXN0LmNvbQB0ZXN0",
		},
		{
			name:          "AUTH with unquoted mechanism and inline response",
			commandLine:   "AUTH PLAIN dGVzdEB0ZXN0LmNvbQB0ZXN0",
			wantMechanism: "PLAIN",
			wantAuthData:  "dGVzdEB0ZXN0LmNvbQB0ZXN0",
		},
		{
			name:          "AUTH with quoted mechanism only",
			commandLine:   `AUTH "PLAIN"`,
			wantMechanism: "PLAIN",
			wantAuthData:  "",
		},
		{
			name:          "AUTH with unquoted mechanism only",
			commandLine:   "AUTH PLAIN",
			wantMechanism: "PLAIN",
			wantAuthData:  "",
		},
		{
			name:          "AUTH with lowercase mechanism",
			commandLine:   "AUTH plain dGVzdEB0ZXN0LmNvbQB0ZXN0",
			wantMechanism: "PLAIN",
			wantAuthData:  "dGVzdEB0ZXN0LmNvbQB0ZXN0",
		},
		{
			name:          "AUTH with quoted lowercase mechanism",
			commandLine:   `AUTH "plain" "dGVzdEB0ZXN0LmNvbQB0ZXN0"`,
			wantMechanism: "PLAIN",
			wantAuthData:  "dGVzdEB0ZXN0LmNvbQB0ZXN0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the command line the same way POP3 session does
			parts := strings.Split(tt.commandLine, " ")
			if len(parts) < 2 {
				t.Fatalf("Failed to parse command: not enough parts")
			}

			// Extract mechanism with quote handling
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

func TestAuthPlainContinuationQuoting(t *testing.T) {
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
			// Simulate continuation response processing (same as in AUTH handler)
			authData := strings.TrimSpace(tt.response)
			authData = server.UnquoteString(authData)

			if authData != tt.wantAuthData {
				t.Errorf("AuthData = %q, want %q", authData, tt.wantAuthData)
			}
		})
	}
}

func TestSASLPlainEncodingPOP3(t *testing.T) {
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
