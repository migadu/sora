package lmtp

import (
	"strings"
	"testing"
)

// Command names and ESMTP parameter names are case-insensitive over US-ASCII only: "ABNF
// strings are case insensitive and the character set for these strings is US-ASCII" (RFC
// 5234 section 2.3). strings.ToUpper maps U+0131 (LATIN SMALL LETTER DOTLESS I) to "I"
// and U+017F (LATIN SMALL LETTER LONG S) to "S": a look-alike is an unknown command, or
// an unknown parameter (555, RFC 5321 section 4.1.1.11).
func TestKeywordLookalikesAreNotKeywords(t *testing.T) {
	_, addr := startWireBackend(t, "lookalike", LMTPServerOptions{MaxMessageSize: 1024})
	for _, tt := range []struct{ line, want string }{
		{"MAıL FROM:<a@example.org>", "500 5.5.2 "},
		{"MAIL FROM:<a@example.org> ſIZE=2048", "555 5.5.4 "},
		{"MAIL FROM:<a@example.org> ſMTPUTF8", "555 5.5.4 "},
		{"mail from:<a@example.org> size=1024 smtputf8", "250 "},
	} {
		c := dialWire(t, addr)
		c.cmd("LHLO client.example.org")
		if resp := c.cmd(tt.line); !strings.HasPrefix(resp[0], tt.want) {
			t.Errorf("%s: %q, want %q", tt.line, resp, tt.want)
		}
	}
}
