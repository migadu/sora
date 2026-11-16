package lmtpproxy

import (
	"io"
	"strings"
	"testing"
)

// Parameter and capability keywords are case-insensitive over US-ASCII only: "ABNF
// strings are case insensitive and the character set for these strings is US-ASCII"
// (RFC 5234 section 2.3). strings.EqualFold matches U+017F (LATIN SMALL LETTER LONG S)
// with "s", so "ſIZE" was read as SIZE and "ſMTPUTF8" as SMTPUTF8.
func TestParameterLookalikesAreNotKeywords(t *testing.T) {
	if size, reply := mailSizeParameter([]string{"FROM:<a@example.org>", "ſIZE=99999999999"}, 1024); size != "" || reply != "" {
		t.Errorf("mailSizeParameter(ſIZE=99999999999) = %q, %q; want no SIZE parameter", size, reply)
	}
	if size, reply := mailSizeParameter([]string{"FROM:<a@example.org>", "ſIZE=1x"}, 1024); size != "" || reply != "" {
		t.Errorf("mailSizeParameter(ſIZE=1x) = %q, %q; want no SIZE parameter", size, reply)
	}
	if hasSMTPUTF8Param([]string{"FROM:<a@example.org>", "ſMTPUTF8"}) {
		t.Error("hasSMTPUTF8Param(ſMTPUTF8) = true, want false")
	}
	if isSMTPUTF8Capability("250-ſMTPUTF8") {
		t.Error(`isSMTPUTF8Capability("250-ſMTPUTF8") = true, want false`)
	}
	if isSIZECapability("250-ſIZE 1024") {
		t.Error(`isSIZECapability("250-ſIZE 1024") = true, want false`)
	}

	// ASCII letters in any case are still the keywords.
	if size, reply := mailSizeParameter([]string{"FROM:<a@example.org>", "size=1024"}, 1024); size != "1024" || reply != "" {
		t.Errorf("mailSizeParameter(size=1024) = %q, %q; want 1024", size, reply)
	}
	if !hasSMTPUTF8Param([]string{"FROM:<a@example.org>", "SmtpUtf8"}) {
		t.Error("hasSMTPUTF8Param(SmtpUtf8) = false, want true")
	}
}

// On the wire a look-alike of SIZE is an unknown parameter, answered as the proxy answers
// any other (555 5.5.4), not as a size it does not declare. A look-alike command name is
// an unknown command.
func TestMAILLookalikesOnTheWire(t *testing.T) {
	conn, r := startSizeDeclarationSession(t, 1024)
	io.WriteString(conn, "LHLO client.example.org\r\n")
	readReply(t, r)

	for _, tt := range []struct{ line, want string }{
		{"MAıL FROM:<a@example.org>", "500 5.5.2 "},
		{"MAIL FROM:<a@example.org> XSIZE=2048", "555 5.5.4 "},
		{"MAIL FROM:<a@example.org> ſIZE=2048", "555 5.5.4 "},
		{"MAIL FROM:<a@example.org> SIZE=2048", "552 5.3.4 "},
	} {
		io.WriteString(conn, tt.line+"\r\n")
		if got := readReply(t, r); !strings.HasPrefix(got, tt.want) {
			t.Errorf("%s: %q, want %q", tt.line, got, tt.want)
		}
		io.WriteString(conn, "RSET\r\n")
		readReply(t, r)
	}
}
