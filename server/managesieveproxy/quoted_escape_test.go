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

// TestManageSieveProxyRefusesInvalidQuotedEscape: the proxy's pre-auth commands are
// parsed by the go-managesieve server, where a backslash in a quoted string may only
// escape DQUOTE or another backslash (RFC 5804 section 4: QUOTED-CHAR =
// SAFE-UTF8-CHAR / "\" QUOTED-SPECIALS, QUOTED-SPECIALS = DQUOTE / "\"). Any other
// escape is a syntax error and the command does not run (#1807); before the fix the
// backslash was dropped, so AUTHENTICATE "PL\AIN" logged the client in. A refused line
// that ends with a non-synchronizing literal has its body on the wire already, and the
// connection is closed rather than reading that body as the next command.
func TestManageSieveProxyRefusesInvalidQuotedEscape(t *testing.T) {
	plain := base64.StdEncoding.EncodeToString([]byte("\x00" + sieveTestUser + "\x00" + sieveTestPassword))
	cases := []struct {
		name   string
		send   string
		closes bool
	}{
		{"AUTHENTICATE mechanism", `AUTHENTICATE "PL\AIN" "` + plain + "\"\r\n", false},
		{"AUTHENTICATE initial response", `AUTHENTICATE "PLAIN" "` + plain[:4] + `\` + plain[4:] + "\"\r\n", false},
		{"NOOP tag", `NOOP "ta\g"` + "\r\n", false},
		{"AUTHENTICATE mechanism, literal response", fmt.Sprintf("AUTHENTICATE \"PL\\AIN\" {%d+}\r\n%s\r\n", len(plain), plain), true},
		// No space is needed before the marker: "PLAIN"{5+} is a mechanism and a literal too.
		{"AUTHENTICATE mechanism, literal response right after the quote", fmt.Sprintf("AUTHENTICATE \"PL\\AIN\"{%d+}\r\n%s\r\n", len(plain), plain), true},
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
				Name:               "quoted-escape",
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
			if got := readLineWithPrefix(t, r, "OK", "NO", "BYE"); !strings.HasPrefix(got, `NO "Invalid command syntax:`) {
				t.Fatalf("%q: reply %q, want NO \"Invalid command syntax: ...\"", tc.send, got)
			}

			if tc.closes {
				if line, err := r.ReadString('\n'); err == nil {
					t.Fatalf("%q: connection still open after the refusal, got %q", tc.send, line)
				}
				conn, r = dialTest(t, addr)
				readLineWithPrefix(t, r, "OK", "NO", "BYE")
			}

			// The session is still not authenticated: a clean login works, and only
			// that login reaches the backend.
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
