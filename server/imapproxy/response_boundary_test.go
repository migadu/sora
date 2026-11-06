package imapproxy

import "testing"

// The stream stands between responses only after a line end outside a literal, however
// the bytes are split into chunks.
func TestResponseBoundary(t *testing.T) {
	cases := []struct {
		name   string
		stream string
		want   bool // between responses at the end
	}{
		{"nothing yet", "", true},
		{"complete line", "* 1 EXISTS\r\n", true},
		{"partial line", "* 1 EXI", false},
		{"literal announced", "* 1 FETCH (BODY[] {5}\r\n", false},
		{"inside the literal", "* 1 FETCH (BODY[] {5}\r\nhel", false},
		{"literal ending in CRLF", "* 1 FETCH (BODY[] {5}\r\nhi\r\n\r", false},
		{"after the literal, line goes on", "* 1 FETCH (BODY[] {5}\r\nhello", false},
		{"response complete", "* 1 FETCH (BODY[] {5}\r\nhello)\r\n", true},
		{"literal that looks like responses", "* 1 FETCH (BODY[] {16}\r\n* 2 EXISTS\r\n{9}\r\n)\r\n", true},
		{"two literals in one response", "* 1 FETCH (BODY[1] {2}\r\nab BODY[2] {3}\r\ncde)\r\n", true},
		{"literal8", "* 1 FETCH (BINARY[1] ~{4}\r\n\x00\x01\r\n)\r\n", true},
		{"non-synchronizing form", "* 1 FETCH (BODY[] {3+}\r\nabc)\r\n", true},
		{"empty literal", "* 1 FETCH (BODY[] {0}\r\n)\r\n", true},
		{"brace that is no literal", "* OK [ALERT] {not a literal}\r\n", true},
		{"continuation request", "+ Ready\r\n", true},
	}
	for _, c := range cases {
		for _, size := range []int{1, 3, 7, 1 << 20} {
			var b responseBoundary
			for i := 0; i < len(c.stream); i += size {
				b.consume([]byte(c.stream[i:min(i+size, len(c.stream))]), false)
			}
			if got := b.atBoundary(); got != c.want {
				t.Errorf("%s (chunks of %d): atBoundary = %v, want %v", c.name, size, got, c.want)
			}
		}
	}
}

// Stopping at the first boundary leaves the rest of the chunk untaken.
func TestResponseBoundary_StopsAtTheFirstBoundary(t *testing.T) {
	var b responseBoundary
	b.consume([]byte("* 1 FETCH (BODY[] {4}\r\nab"), false)
	chunk := []byte("cd)\r\n* 2 EXISTS\r\n")
	n := b.consume(chunk, true)
	if string(chunk[:n]) != "cd)\r\n" || !b.atBoundary() {
		t.Fatalf("stopped after %q (atBoundary %v), want after %q", chunk[:n], b.atBoundary(), "cd)\r\n")
	}
}
