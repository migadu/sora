//go:build integration

package managesieve

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestManageSieve_AuthenticateRefusesNonBase64Response: a SASL PLAIN response with a
// CR or CRLF inside a quoted string or a literal, a backslash inside a quoted string,
// or a continuation line or an unquoted initial response with whitespace or a CR
// around it, is refused and never becomes a login (#1772). RFC 5804
// section 2.1: "A client response consists of a string (quoted or literal) with the
// base-64 encoding of the SASL data followed by a CRLF", and RFC 4648 section 3.3:
// "Implementations MUST reject the encoded data if it contains characters outside the
// base alphabet when interpreting base-encoded data". Before the fix
// base64.StdEncoding skipped the CR and go-managesieve trimmed the whitespace, so
// these valid credentials logged the client in.
func TestManageSieve_AuthenticateRefusesNonBase64Response(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupManageSieveServer(t)
	defer server.Close()

	plain := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
	crInside := plain[:4] + "\r" + plain[4:]
	crlfInside := plain[:4] + "\r\n" + plain[4:]
	cases := []struct{ name, send string }{
		{"quoted initial response, CR inside", `AUTHENTICATE "PLAIN" "` + crInside + "\"\r\n"},
		{"literal initial response, CRLF inside", fmt.Sprintf("AUTHENTICATE \"PLAIN\" {%d+}\r\n%s\r\n", len(crlfInside), crlfInside)},
		{"quoted continuation, CR inside", "AUTHENTICATE \"PLAIN\"\r\n\"" + crInside + "\"\r\n"},
		{"continuation, leading space", "AUTHENTICATE \"PLAIN\"\r\n " + plain + "\r\n"},
		// An unquoted initial response is accepted like a bare continuation line and,
		// like one, runs to the CRLF; a backslash inside a quoted response is no
		// QUOTED-CHAR escape of a base64 character (RFC 5804 section 4).
		{"unquoted initial response, CR before the CRLF", `AUTHENTICATE "PLAIN" ` + plain + "\r\r\n"},
		{"quoted initial response, backslash inside", `AUTHENTICATE "PLAIN" "` + plain[:4] + `\` + plain[4:] + "\"\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", server.Address)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
			r := bufio.NewReader(conn)
			reply := func() string {
				t.Helper()
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						t.Fatalf("read: %v", err)
					}
					if strings.HasPrefix(line, "OK") || strings.HasPrefix(line, "NO") || strings.HasPrefix(line, "BYE") {
						return strings.TrimRight(line, "\r\n")
					}
				}
			}
			if greeting := reply(); !strings.HasPrefix(greeting, "OK") {
				t.Fatalf("greeting: %q", greeting)
			}

			if _, err := conn.Write([]byte(tc.send)); err != nil {
				t.Fatalf("send: %v", err)
			}
			if got := reply(); got != `NO "Invalid authentication data"` {
				t.Fatalf("%q: reply %q, want NO \"Invalid authentication data\"", tc.send, got)
			}

			// The session is still not authenticated: the same credentials sent as
			// plain base64 log in on the same connection.
			if _, err := conn.Write([]byte(`AUTHENTICATE "PLAIN" "` + plain + "\"\r\n")); err != nil {
				t.Fatalf("send: %v", err)
			}
			if got := reply(); !strings.HasPrefix(got, "OK") {
				t.Fatalf("AUTHENTICATE after the refusal: reply %q, want OK", got)
			}
		})
	}
}
