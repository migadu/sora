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
		{"tagged status ending in braces", "a1 NO [NONEXISTENT] mailbox does not exist: missing{64}\r\n", true},
		{"long tagged status", "long-client-command-tag OK completed {8}\r\n", true},
		{"untagged OK text", "* OK [ALERT] notice {8}\r\n", true},
		{"untagged NO text", "* NO failed {8}\r\n", true},
		{"untagged BAD text", "* BAD failed {8}\r\n", true},
		{"untagged BYE text", "* BYE closing {8}\r\n", true},
		{"untagged PREAUTH text", "* PREAUTH ready {8}\r\n", true},
		{"case-insensitive status", "* oK notice {8}\r\n", true},
		{"literal in a status code", "a1 NO [BADCHARSET ({5}\r\n", false},
		{"status code continues after its literal", "a1 NO [BADCHARSET ({5}\r\nUTF-8", false},
		{"text after a status-code literal", "* NO [BADCHARSET ({5}\r\nUTF-8)] failed {64}\r\n", true},
		{"quoted bracket in a status code", "a1 NO [BADCHARSET (\"odd]name\" {5}\r\nUTF-8)] failed {64}\r\n", true},
		{"escaped quote in a status code", "a1 NO [BADCHARSET (\"odd\\\"]name\" {5}\r\nUTF-8)] failed {64}\r\n", true},
		{"bracket inside a status-code literal", "a1 NO [BADCHARSET ({5}\r\n]UTF-)] failed {64}\r\n", true},
		{"spaces begin ordinary status text", "a1 NO  [notice {8}\r\n", true},
		{"continuation ending in braces", "+ Ready {8}\r\n", true},
		{"continuation with a response code", "+ [ALERT] Ready {8}\r\n", true},
		{"data type shares a status prefix", "* OKAY {5}\r\n", false},
		{"list mailbox literal", "* LIST () \"/\" {5}\r\nINBOX\r\n", true},
		{"literal continuation is not a new response", "* X {2}\r\nab {3}\r\ncde\r\n", true},
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

func TestResponseBoundary_StopsAfterStatusText(t *testing.T) {
	for _, status := range []string{
		"a1 NO [NONEXISTENT] mailbox does not exist: missing{64}\r\n",
		"* NO [BADCHARSET ({5}\r\nUTF-8)] failed {64}\r\n",
		"+ Ready {64}\r\n",
	} {
		var b responseBoundary
		chunk := status + "* 1 FETCH (BODY[] {4}\r\nab"
		n := b.consume([]byte(chunk), true)
		if n != len(status) || !b.atBoundary() {
			t.Errorf("stopped after %q (atBoundary %v), want after %q", chunk[:n], b.atBoundary(), status)
		}
	}
}
