package pop3

import (
	"bufio"
	"bytes"
	"strings"
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
		// Bare-LF and mixed line endings: common in imported/maildir mail.
		// The termination octet must be stuffed regardless of the source
		// line-ending convention, and the output must be CRLF-framed so the
		// multiline terminator is unambiguous (RFC 1939 §3).
		{
			name:     "Bare LF dot terminator (imported maildir)",
			input:    "Line 1\n.\nLine 2",
			expected: "Line 1\r\n..\r\nLine 2",
		},
		{
			name:     "Bare LF dot at line start",
			input:    ".Line 1\nLine 2\n.Line 3",
			expected: "..Line 1\r\nLine 2\r\n..Line 3",
		},
		{
			name:     "Mixed CRLF and LF endings",
			input:    "A\r\nB\n.C\r\nD",
			expected: "A\r\nB\r\n..C\r\nD",
		},
		{
			name:     "Bare LF terminator line then trailing newline",
			input:    "body\n.\n",
			expected: "body\r\n..\r\n",
		},
		{
			name:     "Bare LF HTML email with dot",
			input:    "Content-Type: text/html\n\n<html>\n.\n</html>",
			expected: "Content-Type: text/html\r\n\r\n<html>\r\n..\r\n</html>",
		},
		{
			name:     "CRLF preserved with trailing newline",
			input:    "a\r\nb\r\n",
			expected: "a\r\nb\r\n",
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

func TestCrlfNormalizedLen(t *testing.T) {
	tests := []struct {
		name string
		body string
		want int
	}{
		{"already CRLF", "a\r\nb\r\n", 6},
		{"bare LF", "a\nb\n", 6},
		{"mixed", "a\r\nb\nc", 7},
		{"no terminator", "abc", 3},
		{"empty", "", 0},
		{"blank line separator bare LF", "H: v\n\nbody", len("H: v\r\n\r\nbody")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := crlfNormalizedLen([]byte(tt.body)); got != tt.want {
				t.Errorf("crlfNormalizedLen(%q) = %d, want %d", tt.body, got, tt.want)
			}
		})
	}
}

// streamDotStuffed runs writeDotStuffedBody into a string for testing.
func streamDotStuffed(body string) string {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	writeDotStuffedBody(bw, []byte(body))
	_ = bw.Flush()
	return buf.String()
}

// TestWriteDotStuffedBody verifies the streaming stuffer produces the same
// CRLF-normalized, dot-stuffed body (without the terminator) as the batch
// dotStuffPOP3 used by TOP, including for bare-LF and mixed line endings.
func TestWriteDotStuffedBody(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"bare LF dot terminator", "Line 1\n.\nLine 2", "Line 1\r\n..\r\nLine 2"},
		{"bare LF dot at line start", ".Line 1\nLine 2\n.Line 3", "..Line 1\r\nLine 2\r\n..Line 3"},
		{"mixed endings", "A\r\nB\n.C\r\nD", "A\r\nB\r\n..C\r\nD"},
		{"trailing newline", "body\n.\n", "body\r\n..\r\n"},
		{"CRLF preserved", "a\r\nb\r\n", "a\r\nb\r\n"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := streamDotStuffed(tt.input); got != tt.expected {
				t.Errorf("writeDotStuffedBody(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestRETRBodyLengthInvariant guards the RETR octet-count contract: the announced
// count crlfNormalizedLen(body) equals the unstuffed length of the streamed body,
// so a byte-counting client reads exactly the right number of octets.
func TestRETRBodyLengthInvariant(t *testing.T) {
	bodies := []string{
		"Line 1\n.\nLine 2",
		".Line 1\nLine 2\n.Line 3",
		"A\r\nB\n.C\r\nD",
		"body\n.\n",
		"Content-Type: text/html\n\n<html>\n.\n</html>",
		"a\r\nb\r\n",
		"plain body no dots\nsecond line\n",
	}
	for _, body := range bodies {
		want := crlfNormalizedLen([]byte(body))
		got := len(unstuffForTest(streamDotStuffed(body)))
		if got != want {
			t.Errorf("unstuffed length %d != crlfNormalizedLen %d for %q", got, want, body)
		}
	}
}

// unstuffForTest reverses POP3 dot-stuffing: any line beginning with ".." loses
// one leading dot. Mirrors what a conforming client does on receipt.
func unstuffForTest(s string) string {
	lines := strings.Split(s, "\r\n")
	for i, line := range lines {
		if strings.HasPrefix(line, ".") {
			lines[i] = line[1:]
		}
	}
	return strings.Join(lines, "\r\n")
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
