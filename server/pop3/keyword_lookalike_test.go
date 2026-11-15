package pop3

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// Command keywords and SASL mechanism names are case-insensitive over ASCII only (RFC
// 1939 section 3: "Commands in the POP3 consist of a case-insensitive keyword [...]
// Keywords and arguments consist of printable ASCII characters"; RFC 4422 section 3.1).
// strings.ToUpper maps U+0131 (LATIN SMALL LETTER DOTLESS I) to "I" and U+017F (LATIN
// SMALL LETTER LONG S) to "S": a look-alike is an unknown command or mechanism. Each
// -ERR waits out the error delay, so the connections run in parallel.
func TestKeywordLookalikesAreNotKeywords(t *testing.T) {
	addr := startGlobalTLSTestServer(t, POP3ServerOptions{})
	for _, tt := range []struct{ line, want string }{
		{"UſER user@example.com", "-ERR"},
		{"QUıT", "-ERR"},
		{"AUTH PLAıN", "-ERR"},
		{"user user@example.com", "+OK"},
	} {
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			r := bufio.NewReader(conn)
			if greeting, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(greeting, "+OK") {
				t.Fatalf("greeting = %q, %v", greeting, err)
			}
			conn.Write([]byte(tt.line + "\r\n"))
			if got, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(got, tt.want) {
				t.Errorf("%s: %q, %v; want %q", tt.line, got, err, tt.want)
			}
		})
	}
}

// LANG takes a language range (RFC 6856 section 3, RFC 4647 section 2.1), ASCII letters,
// digits and hyphens compared case-insensitively. strings.ToLower maps U+0130 (LATIN
// CAPITAL LETTER I WITH DOT ABOVE) to "i", so "İ-DEFAULT" was taken for i-default.
func TestSetLanguageMatchesASCIIOnly(t *testing.T) {
	ctx := context.Background()
	s := &POP3Session{}
	if tag, err := s.SetLanguage(ctx, "İ-DEFAULT"); err == nil {
		t.Errorf("SetLanguage(İ-DEFAULT) = %q, want an error", tag)
	}
	for lang, want := range map[string]string{"I-Default": "i-default", "EN": "en", "*": "en"} {
		if tag, err := s.SetLanguage(ctx, lang); err != nil || tag != want {
			t.Errorf("SetLanguage(%s) = %q, %v; want %q", lang, tag, err, want)
		}
	}
}
