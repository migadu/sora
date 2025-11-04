package pop3

import (
	"testing"
)

func TestDotStuffPOP3(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "No dots",
			input:    "Line 1\r\nLine 2\r\nLine 3",
			expected: "Line 1\r\nLine 2\r\nLine 3",
		},
		{
			name:     "Dot at start of line",
			input:    ".Line 1\r\nLine 2\r\n.Line 3",
			expected: "..Line 1\r\nLine 2\r\n..Line 3",
		},
		{
			name:     "Dot terminator in body",
			input:    "Line 1\r\n.\r\nLine 2",
			expected: "Line 1\r\n..\r\nLine 2",
		},
		{
			name:     "Multiple dots at line start",
			input:    "..Already stuffed\r\n.Another",
			expected: "...Already stuffed\r\n..Another",
		},
		{
			name:     "Dot in middle of line (no stuffing needed)",
			input:    "This is a . in the middle\r\nAnother line",
			expected: "This is a . in the middle\r\nAnother line",
		},
		{
			name:     "Empty message",
			input:    "",
			expected: "",
		},
		{
			name:     "Single dot",
			input:    ".",
			expected: "..",
		},
		{
			name:     "Just terminator sequence",
			input:    ".\r\n",
			expected: "..\r\n",
		},
		{
			name:     "Real-world HTML email with dots",
			input:    "Content-Type: text/html\r\n\r\n<html>\r\n.\r\n</html>",
			expected: "Content-Type: text/html\r\n\r\n<html>\r\n..\r\n</html>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dotStuffPOP3(tt.input)
			if result != tt.expected {
				t.Errorf("dotStuffPOP3() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func BenchmarkDotStuffPOP3_NoDots(b *testing.B) {
	input := "Line 1\r\nLine 2\r\nLine 3\r\nLine 4\r\nLine 5\r\n"
	for i := 0; i < b.N; i++ {
		dotStuffPOP3(input)
	}
}

func BenchmarkDotStuffPOP3_WithDots(b *testing.B) {
	input := ".Line 1\r\nLine 2\r\n.Line 3\r\nLine 4\r\n.Line 5\r\n"
	for i := 0; i < b.N; i++ {
		dotStuffPOP3(input)
	}
}

func BenchmarkDotStuffPOP3_LargeMessage(b *testing.B) {
	// Simulate a 10KB message with occasional dots
	var input string
	for i := 0; i < 100; i++ {
		if i%10 == 0 {
			input += ".Line with dot at start\r\n"
		} else {
			input += "Regular line without dot at start\r\n"
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dotStuffPOP3(input)
	}
}
