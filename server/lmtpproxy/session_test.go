package lmtpproxy

import (
	"testing"

	"github.com/migadu/sora/server"
)

func TestExtractAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "basic angle bracket address",
			input:    "<user@example.com>",
			expected: "user@example.com",
		},
		{
			name:     "address with NOTIFY parameter",
			input:    "<user@example.com> NOTIFY=NEVER",
			expected: "user@example.com",
		},
		{
			name:     "address with ORCPT parameter",
			input:    "<user@example.com> ORCPT=rfc822;user@example.com",
			expected: "user@example.com",
		},
		{
			name:     "address with multiple parameters",
			input:    "<user@example.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;user@example.com",
			expected: "user@example.com",
		},
		{
			name:     "empty sender (null)",
			input:    "<>",
			expected: "",
		},
		{
			name:     "empty sender with SIZE parameter",
			input:    "<> SIZE=1234",
			expected: "",
		},
		{
			name:     "address without angle brackets",
			input:    "user@example.com",
			expected: "user@example.com",
		},
		{
			name:     "address without angle brackets with space",
			input:    "user@example.com SIZE=1234",
			expected: "user@example.com",
		},
		{
			name:     "address with no closing bracket (invalid)",
			input:    "<user@example.com",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal session for testing
			s := &Session{
				server: &Server{},
			}
			result := s.extractAddress(tt.input)
			if result != tt.expected {
				t.Errorf("extractAddress(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFindParameter(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		prefix   string
		expected string
		found    bool
	}{
		{
			name:     "TO: with space",
			args:     []string{"TO:", "<user@example.com>", "NOTIFY=NEVER"},
			prefix:   "TO:",
			expected: "<user@example.com>",
			found:    true,
		},
		{
			name:     "TO: without space",
			args:     []string{"TO:<user@example.com>", "NOTIFY=NEVER"},
			prefix:   "TO:",
			expected: "<user@example.com>",
			found:    true,
		},
		{
			name:     "FROM: with space",
			args:     []string{"FROM:", "<sender@example.com>", "SIZE=1234"},
			prefix:   "FROM:",
			expected: "<sender@example.com>",
			found:    true,
		},
		{
			name:     "FROM: without space",
			args:     []string{"FROM:<sender@example.com>", "SIZE=1234"},
			prefix:   "FROM:",
			expected: "<sender@example.com>",
			found:    true,
		},
		{
			name:     "parameter not found",
			args:     []string{"SIZE=1234"},
			prefix:   "TO:",
			expected: "",
			found:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, found := findParameter(tt.args, tt.prefix)
			if found != tt.found {
				t.Errorf("findParameter(%v, %q) found = %v, want %v", tt.args, tt.prefix, found, tt.found)
			}
			if result != tt.expected {
				t.Errorf("findParameter(%v, %q) = %q, want %q", tt.args, tt.prefix, result, tt.expected)
			}
		})
	}
}

func TestRCPTWithESMTPParameters(t *testing.T) {
	// Test that ParseLine + findParameter + extractAddress work together correctly
	tests := []struct {
		name            string
		commandLine     string
		expectedCommand string
		expectedAddress string
	}{
		{
			name:            "RCPT with NOTIFY parameter",
			commandLine:     "RCPT TO:<user@example.com> NOTIFY=NEVER",
			expectedCommand: "RCPT",
			expectedAddress: "user@example.com",
		},
		{
			name:            "RCPT with ORCPT parameter",
			commandLine:     "RCPT TO:<user@example.com> ORCPT=rfc822;user@example.com",
			expectedCommand: "RCPT",
			expectedAddress: "user@example.com",
		},
		{
			name:            "RCPT with multiple parameters",
			commandLine:     "RCPT TO:<user@example.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;user@example.com",
			expectedCommand: "RCPT",
			expectedAddress: "user@example.com",
		},
		{
			name:            "MAIL with SIZE parameter",
			commandLine:     "MAIL FROM:<sender@example.com> SIZE=12345",
			expectedCommand: "MAIL",
			expectedAddress: "sender@example.com",
		},
		{
			name:            "RCPT with space after TO:",
			commandLine:     "RCPT TO: <user@example.com> NOTIFY=NEVER",
			expectedCommand: "RCPT",
			expectedAddress: "user@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the command line
			_, command, args, err := server.ParseLine(tt.commandLine, false)
			if err != nil {
				t.Fatalf("ParseLine failed: %v", err)
			}
			if command != tt.expectedCommand {
				t.Errorf("command = %q, want %q", command, tt.expectedCommand)
			}

			// Find the parameter (TO: or FROM:)
			var prefix string
			if command == "RCPT" {
				prefix = "TO:"
			} else if command == "MAIL" {
				prefix = "FROM:"
			}

			param, found := findParameter(args, prefix)
			if !found {
				t.Fatalf("findParameter(%v, %q) not found", args, prefix)
			}

			// Extract the address
			s := &Session{server: &Server{}}
			address := s.extractAddress(param)
			if address != tt.expectedAddress {
				t.Errorf("extractAddress(%q) = %q, want %q", param, address, tt.expectedAddress)
			}
		})
	}
}
