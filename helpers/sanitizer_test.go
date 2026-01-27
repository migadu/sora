package helpers

import (
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
)

func TestSanitizeFlags(t *testing.T) {
	tests := []struct {
		name     string
		input    []imap.Flag
		expected []imap.Flag
	}{
		{
			name:     "Empty flags",
			input:    []imap.Flag{},
			expected: []imap.Flag{},
		},
		{
			name:     "Valid flags only",
			input:    []imap.Flag{"$Valid", "$Important", "\\Seen"},
			expected: []imap.Flag{"$Valid", "$Important", "\\Seen"},
		},
		{
			name:     "NIL flag (uppercase)",
			input:    []imap.Flag{"$Valid", "NIL", "$Another"},
			expected: []imap.Flag{"$Valid", "$Another"},
		},
		{
			name:     "NIL flag (lowercase)",
			input:    []imap.Flag{"$Valid", "nil", "$Another"},
			expected: []imap.Flag{"$Valid", "$Another"},
		},
		{
			name:     "$NIL flag",
			input:    []imap.Flag{"$Valid", "$NIL", "$Another"},
			expected: []imap.Flag{"$Valid", "$Another"},
		},
		{
			name:     "$nil flag (lowercase)",
			input:    []imap.Flag{"$Valid", "$nil", "$Another"},
			expected: []imap.Flag{"$Valid", "$Another"},
		},
		{
			name:     "NULL flag (uppercase)",
			input:    []imap.Flag{"$Valid", "NULL", "$Another"},
			expected: []imap.Flag{"$Valid", "$Another"},
		},
		{
			name:     "null flag (lowercase)",
			input:    []imap.Flag{"$Valid", "null", "$Another"},
			expected: []imap.Flag{"$Valid", "$Another"},
		},
		{
			name:     "$NULL flag",
			input:    []imap.Flag{"$Valid", "$NULL", "$Another"},
			expected: []imap.Flag{"$Valid", "$Another"},
		},
		{
			name:     "Empty string flag",
			input:    []imap.Flag{"$Valid", "", "$Another"},
			expected: []imap.Flag{"$Valid", "$Another"},
		},
		{
			name:     "Whitespace-only flag",
			input:    []imap.Flag{"$Valid", "   ", "$Another"},
			expected: []imap.Flag{"$Valid", "$Another"},
		},
		{
			name:     "Multiple invalid flags",
			input:    []imap.Flag{"$Valid", "NIL", "", "NULL", "   ", "$Another"},
			expected: []imap.Flag{"$Valid", "$Another"},
		},
		{
			name:     "All invalid flags",
			input:    []imap.Flag{"NIL", "NULL", "", "   "},
			expected: []imap.Flag{},
		},
		{
			name:     "Mixed case NIL",
			input:    []imap.Flag{"$Valid", "Nil", "nIL", "$Another"},
			expected: []imap.Flag{"$Valid", "$Another"},
		},
		{
			name:     "Flags containing NIL as substring",
			input:    []imap.Flag{"$Valid", "$NOTNIL", "$Another"},
			expected: []imap.Flag{"$Valid", "$Another"}, // Should filter out because contains NIL
		},
		{
			name:     "System flags with NIL-like names",
			input:    []imap.Flag{"\\Seen", "\\Deleted", "NIL", "$Valid"},
			expected: []imap.Flag{"\\Seen", "\\Deleted", "$Valid"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeFlags(tt.input)

			// Check length
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d flags, got %d\nInput: %v\nExpected: %v\nGot: %v",
					len(tt.expected), len(result), tt.input, tt.expected, result)
				return
			}

			// Check each flag
			for i, flag := range result {
				if flag != tt.expected[i] {
					t.Errorf("Flag mismatch at index %d: expected %q, got %q",
						i, tt.expected[i], flag)
				}
			}
		})
	}
}

func TestSanitizeFlags_NilInput(t *testing.T) {
	result := SanitizeFlags(nil)
	if result != nil {
		t.Errorf("Expected nil for nil input, got %v", result)
	}
}

func TestSanitizeFlags_PreservesOrder(t *testing.T) {
	input := []imap.Flag{"$Zebra", "$Apple", "$Middle"}
	result := SanitizeFlags(input)

	expected := []imap.Flag{"$Zebra", "$Apple", "$Middle"}
	if len(result) != len(expected) {
		t.Fatalf("Length mismatch: expected %d, got %d", len(expected), len(result))
	}

	for i, flag := range result {
		if flag != expected[i] {
			t.Errorf("Order not preserved at index %d: expected %q, got %q",
				i, expected[i], flag)
		}
	}
}

func TestSanitizeUTF8(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Valid UTF-8 string",
			input:    "Hello, World!",
			expected: "Hello, World!",
		},
		{
			name:     "UTF-8 with emoji",
			input:    "Hello 👋 World 🌍",
			expected: "Hello 👋 World 🌍",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "String with NULL byte at start",
			input:    "\x00Hello",
			expected: "Hello",
		},
		{
			name:     "String with NULL byte in middle",
			input:    "Hello\x00World",
			expected: "HelloWorld",
		},
		{
			name:     "String with NULL byte at end",
			input:    "Hello\x00",
			expected: "Hello",
		},
		{
			name:     "String with multiple NULL bytes",
			input:    "Hello\x00\x00World\x00",
			expected: "HelloWorld",
		},
		{
			name:     "String with only NULL bytes",
			input:    "\x00\x00\x00",
			expected: "",
		},
		{
			name:     "String with invalid UTF-8 sequences",
			input:    "Hello\xFFWorld",
			expected: "HelloWorld",
		},
		{
			name:     "String with NULL bytes and invalid UTF-8",
			input:    "Hello\x00\xFFWorld\x00",
			expected: "HelloWorld",
		},
		{
			name:     "Real-world case: message with NULL bytes",
			input:    "Subject: Test\x00\nFrom: sender@example.com\x00",
			expected: "Subject: Test\nFrom: sender@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeUTF8(tt.input)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}

			// Verify result contains no NULL bytes
			if strings.ContainsRune(result, '\x00') {
				t.Errorf("Result still contains NULL bytes: %q", result)
			}
		})
	}
}
