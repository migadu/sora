package pop3

import (
	"testing"
)

// crlfNormalizedLen provides the octet count RETR announces ("+OK nn octets"):
// the CRLF-normalized, unstuffed body length the client reconstructs. The
// dot-stuffing/normalization itself lives in go-pop3 (pop3server/dotstuff.go)
// and is tested there; this test pins the announced count to that definition.
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
		// Lone CRs are content, not line endings: the library streams them
		// verbatim (pop3server TestDotStuffWriter_BareCRContent /
		// TestDotStuffWriter_OctetInvariant pin the writer side), so they
		// add nothing to the announced count.
		{"bare CR mid-line", "a\rb\r\n", 5},
		{"bare CR then bare LF", "a\rb\n", 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := crlfNormalizedLen([]byte(tt.body)); got != tt.want {
				t.Errorf("crlfNormalizedLen(%q) = %d, want %d", tt.body, got, tt.want)
			}
		})
	}
}
