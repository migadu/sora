package managesieve

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// Command names and SASL mechanism names are case-insensitive over US-ASCII only (RFC
// 5804 section 4 defines them in ABNF, whose "strings are case insensitive and the
// character set for these strings is US-ASCII", RFC 5234 section 2.3; RFC 4422 section
// 3.1). strings.ToUpper maps U+0131 (LATIN SMALL LETTER DOTLESS I) to "I": a look-alike
// is an unknown command or mechanism.
func TestKeywordLookalikesAreNotKeywords(t *testing.T) {
	_, addr := startListenerTestServer(t, ManageSieveServerOptions{})
	for _, tt := range []struct{ line, want string }{
		{"CAPABıLITY", "NO"},
		// Without an initial response: PLAIN gets the empty challenge `""`.
		{`AUTHENTICATE "PLAıN"`, "NO"},
		{"capability", `"IMPLEMENTATION"`},
		{`AUTHENTICATE "plain"`, `""`},
	} {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(conn)
		for { // the greeting ends with OK
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("greeting: %v", err)
			}
			if strings.HasPrefix(line, "OK") {
				break
			}
		}
		conn.Write([]byte(tt.line + "\r\n"))
		if got, err := r.ReadString('\n'); err != nil || !strings.HasPrefix(got, tt.want) {
			t.Errorf("%s: first line %q, %v; want %q", tt.line, got, err, tt.want)
		}
		conn.Close()
	}
}
