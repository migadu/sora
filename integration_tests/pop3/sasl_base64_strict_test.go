//go:build integration

package pop3_test

import (
	"bufio"
	"encoding/base64"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
)

// TestPOP3_AuthPlainRefusesNonBase64Response: a SASL PLAIN response with a CR inside
// it or before the CRLF, or with whitespace around it, is refused and never becomes a
// login (#1772). RFC 5034 section 4: "If the server cannot Base64 decode a client
// response, it MUST reject the AUTH command with an -ERR reply. [...] In particular,
// servers and clients MUST reject (and not ignore) any character not explicitly
// allowed by the Base64 alphabet". Before the fix base64.StdEncoding skipped the CR
// and go-pop3 trimmed the whitespace, so these valid credentials logged the client in.
func TestPOP3_AuthPlainRefusesNonBase64Response(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()

	plain := base64.StdEncoding.EncodeToString([]byte("\x00" + account.Email + "\x00" + account.Password))
	cases := []struct{ name, send string }{
		{"initial response, CR before the CRLF", "AUTH PLAIN " + plain + "\r\r\n"},
		{"initial response, text after it", "AUTH PLAIN " + plain + " " + plain[:4] + "\r\n"},
		{"continuation, CR inside", "AUTH PLAIN\r\n" + plain[:4] + "\r" + plain[4:] + "\r\n"},
		{"continuation, leading space", "AUTH PLAIN\r\n " + plain + "\r\n"},
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
					if strings.HasPrefix(line, "+OK") || strings.HasPrefix(line, "-ERR") {
						return strings.TrimRight(line, "\r\n")
					}
				}
			}
			reply() // greeting

			if _, err := conn.Write([]byte(tc.send)); err != nil {
				t.Fatalf("send: %v", err)
			}
			if got := reply(); got != "-ERR Invalid SASL PLAIN response" {
				t.Fatalf("%q: reply %q, want -ERR Invalid SASL PLAIN response", tc.send, got)
			}

			// The session is still not authenticated: the same credentials sent as
			// plain base64 log in on the same connection.
			if _, err := conn.Write([]byte("AUTH PLAIN " + plain + "\r\n")); err != nil {
				t.Fatalf("send: %v", err)
			}
			if got := reply(); !strings.HasPrefix(got, "+OK") {
				t.Fatalf("AUTH PLAIN after the refusal: reply %q, want +OK", got)
			}
		})
	}
}
