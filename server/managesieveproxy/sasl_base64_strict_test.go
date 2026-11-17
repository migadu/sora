package managesieveproxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
)

// TestManageSieveProxyAuthenticateRefusesNonBase64Response: the proxy's pre-auth
// AUTHENTICATE exchange is the go-managesieve server's. A SASL PLAIN response with a
// CR or CRLF inside a quoted string or a literal, a backslash inside a quoted string,
// or a continuation line or an unquoted initial response with whitespace or a CR
// around it, must be refused there and never become a login (#1772). RFC
// 5804 section 2.1: "A client response consists of a string (quoted or literal) with
// the base-64 encoding of the SASL data followed by a CRLF", and RFC 4648 section 3.3:
// "Implementations MUST reject the encoded data if it contains characters outside the
// base alphabet when interpreting base-encoded data". Before the fix base64.StdEncoding
// skipped the CR and the library trimmed the whitespace, so these valid credentials
// logged the client in.
func TestManageSieveProxyAuthenticateRefusesNonBase64Response(t *testing.T) {
	plain := base64.StdEncoding.EncodeToString([]byte("\x00" + sieveTestUser + "\x00" + sieveTestPassword))
	crInside := plain[:4] + "\r" + plain[4:]
	crlfInside := plain[:4] + "\r\n" + plain[4:]
	cases := []struct{ name, send string }{
		{"quoted initial response, CR inside", `AUTHENTICATE "PLAIN" "` + crInside + "\"\r\n"},
		{"literal initial response, CRLF inside", fmt.Sprintf("AUTHENTICATE \"PLAIN\" {%d+}\r\n%s\r\n", len(crlfInside), crlfInside)},
		{"quoted continuation, CR inside", "AUTHENTICATE \"PLAIN\"\r\n\"" + crInside + "\"\r\n"},
		{"continuation, leading space", "AUTHENTICATE \"PLAIN\"\r\n " + plain + "\r\n"},
		// An unquoted initial response is accepted like a bare continuation line and,
		// like one, runs to the CRLF. A valid quoted-pair encodes a literal
		// backslash, so parsing succeeds before base64 validation refuses it.
		{"unquoted initial response, CR before the CRLF", `AUTHENTICATE "PLAIN" ` + plain + "\r\r\n"},
		{"quoted initial response, backslash inside", `AUTHENTICATE "PLAIN" "` + plain[:4] + `\\` + plain[4:] + "\"\r\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backendAddr, commands := fakeSieveBackend{}.start(t)
			lookupSrv := httptest.NewServer(acceptingSieveLookup(t))
			t.Cleanup(lookupSrv.Close)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := ln.Addr().String()
			ln.Close()
			// No database: the remote lookup answers every login (proxy-only mode).
			srv, err := New(context.Background(), nil, "localhost", ServerOptions{
				Name:               "sasl-base64",
				Addr:               addr,
				RemoteAddrs:        []string{backendAddr},
				ConnectTimeout:     2 * time.Second,
				InsecureAuth:       true,
				MasterSASLUsername: "proxy-master",
				MasterSASLPassword: "proxy-master-secret",
				RemoteLookup:       &config.RemoteLookupConfig{Enabled: true, URL: lookupSrv.URL + "/lookup?email=$email", Timeout: "5s"},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			go func() { _ = srv.Start() }()
			t.Cleanup(func() { srv.Stop() })

			conn, r := dialTest(t, addr)
			if greeting := readLineWithPrefix(t, r, "OK", "NO", "BYE"); !strings.HasPrefix(greeting, "OK") {
				t.Fatalf("greeting: %q", greeting)
			}
			if _, err := conn.Write([]byte(tc.send)); err != nil {
				t.Fatalf("send: %v", err)
			}
			if got := readLineWithPrefix(t, r, "OK", "NO", "BYE"); got != `NO "Invalid authentication data"` {
				t.Fatalf("%q: reply %q, want NO \"Invalid authentication data\"", tc.send, got)
			}

			// The session is still not authenticated: the same credentials sent as
			// plain base64 log in on the same connection, and only that login
			// reaches the backend.
			if _, err := conn.Write([]byte(`AUTHENTICATE "PLAIN" "` + plain + "\"\r\n")); err != nil {
				t.Fatalf("send: %v", err)
			}
			if got := readLineWithPrefix(t, r, "OK", "NO", "BYE"); got != `OK "Authenticated"` {
				t.Fatalf("AUTHENTICATE after the refusal: reply %q, want OK", got)
			}
			conn.Close()
			logins := 0
			for _, cmd := range commands() {
				if strings.HasPrefix(cmd, "AUTHENTICATE") {
					logins++
				}
			}
			if logins != 1 {
				t.Errorf("the backend saw %d AUTHENTICATE commands, want 1 (the clean login)", logins)
			}
		})
	}
}
