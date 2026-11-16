package lmtpproxy

import (
	"slices"
	"testing"

	"github.com/migadu/sora/server"
)

func TestExtractAddress(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		expected   string
		unreadable bool
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
			name:       "address with no closing bracket (invalid)",
			input:      "<user@example.com",
			unreadable: true,
		},
		{
			name:       "opening bracket only (invalid)",
			input:      "<",
			unreadable: true,
		},
		{
			name:       "one character (invalid)",
			input:      "x",
			unreadable: true,
		},
		{
			name:       "quoted null path (invalid)",
			input:      `"<>"`,
			unreadable: true,
		},
		{
			name:     "quoted address",
			input:    `"<user@example.com>"`,
			expected: "user@example.com",
		},
		{
			name:       "null path with trailing domain (invalid)",
			input:      "<>@example.org",
			unreadable: true,
		},
		{
			name:       "null path followed by second path (invalid)",
			input:      "<><sender@example.org>",
			unreadable: true,
		},
		{
			name:       "angle bracket address with trailing domain (invalid)",
			input:      "<user@example.com>@other.org",
			unreadable: true,
		},
		{
			name:       "angle bracket address with unseparated parameter (invalid)",
			input:      "<user@example.com>SIZE=1234",
			unreadable: true,
		},
		{
			name:       "quoted address with trailing parameter (invalid)",
			input:      `"<user@example.com> NOTIFY=NEVER"`,
			unreadable: true,
		},
		{
			name:       "unclosed quoted address (invalid)",
			input:      `"<user@example.com>`,
			unreadable: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal session for testing
			s := &Session{
				server: &Server{},
			}
			result, ok := s.extractAddress(tt.input)
			if result != tt.expected || ok == tt.unreadable {
				t.Errorf("extractAddress(%q) = %q, %v, want %q, %v", tt.input, result, ok, tt.expected, !tt.unreadable)
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
		params   []string
		found    bool
	}{
		{
			name:     "TO: with space",
			args:     []string{"TO:", "<user@example.com>", "NOTIFY=NEVER"},
			prefix:   "TO:",
			expected: "<user@example.com>",
			params:   []string{"NOTIFY=NEVER"},
			found:    true,
		},
		{
			name:     "TO: without space",
			args:     []string{"TO:<user@example.com>", "NOTIFY=NEVER"},
			prefix:   "TO:",
			expected: "<user@example.com>",
			params:   []string{"NOTIFY=NEVER"},
			found:    true,
		},
		{
			name:     "FROM: with space",
			args:     []string{"FROM:", "<sender@example.com>", "SIZE=1234"},
			prefix:   "FROM:",
			expected: "<sender@example.com>",
			params:   []string{"SIZE=1234"},
			found:    true,
		},
		{
			name:     "FROM: without space",
			args:     []string{"FROM:<sender@example.com>", "SIZE=1234", "SMTPUTF8"},
			prefix:   "FROM:",
			expected: "<sender@example.com>",
			params:   []string{"SIZE=1234", "SMTPUTF8"},
			found:    true,
		},
		{
			name:     "no parameters",
			args:     []string{"from:<sender@example.com>"},
			prefix:   "FROM:",
			expected: "<sender@example.com>",
			found:    true,
		},
		{
			name:   "parameter not found",
			args:   []string{"SIZE=1234"},
			prefix: "TO:",
			found:  false,
		},
		{
			name:   "parameter before the path",
			args:   []string{"NOTIFY=NEVER", "TO:<user@example.com>"},
			prefix: "TO:",
			found:  false,
		},
		{
			name:   "prefix without a path",
			args:   []string{"TO:"},
			prefix: "TO:",
			found:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, params, found := findParameter(tt.args, tt.prefix)
			if found != tt.found {
				t.Errorf("findParameter(%v, %q) found = %v, want %v", tt.args, tt.prefix, found, tt.found)
			}
			if result != tt.expected {
				t.Errorf("findParameter(%v, %q) = %q, want %q", tt.args, tt.prefix, result, tt.expected)
			}
			if !slices.Equal(params, tt.params) {
				t.Errorf("findParameter(%v, %q) params = %q, want %q", tt.args, tt.prefix, params, tt.params)
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
			switch command {
			case "RCPT":
				prefix = "TO:"
			case "MAIL":
				prefix = "FROM:"
			}

			param, _, found := findParameter(args, prefix)
			if !found {
				t.Fatalf("findParameter(%v, %q) not found", args, prefix)
			}

			// Extract the address
			s := &Session{server: &Server{}}
			address, ok := s.extractAddress(param)
			if !ok || address != tt.expectedAddress {
				t.Errorf("extractAddress(%q) = %q, %v, want %q, true", param, address, ok, tt.expectedAddress)
			}
		})
	}
}
