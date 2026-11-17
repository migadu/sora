package pop3proxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"golang.org/x/crypto/bcrypt"
)

// TestPOP3ProxyAuthPlainRefusesNonBase64Response: the proxy's pre-auth AUTH exchange
// is the go-pop3 server's. A SASL PLAIN response with a CR inside it or before the
// CRLF, or with whitespace around it, must be refused there and never become a login
// (#1772). RFC 5034 section 4: "If the server cannot Base64 decode a client response,
// it MUST reject the AUTH command with an -ERR reply. [...] In particular, servers and
// clients MUST reject (and not ignore) any character not explicitly allowed by the
// Base64 alphabet". Before the fix base64.StdEncoding skipped the CR and the library
// trimmed the whitespace, so these valid credentials logged the client in.
func TestPOP3ProxyAuthPlainRefusesNonBase64Response(t *testing.T) {
	const user, password = "user@example.com", "secret"
	plain := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + password))
	cases := []struct{ name, send string }{
		{"initial response, CR before the CRLF", "AUTH PLAIN " + plain + "\r\r\n"},
		{"initial response, text after it", "AUTH PLAIN " + plain + " " + plain[:4] + "\r\n"},
		{"continuation, CR inside", "AUTH PLAIN\r\n" + plain[:4] + "\r" + plain[4:] + "\r\n"},
		{"continuation, leading space", "AUTH PLAIN\r\n " + plain + "\r\n"},
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"address": r.URL.Query().Get("email"), "password_hash": string(hash)})
	}))
	t.Cleanup(lookup.Close)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backendAddr, authzids := authzidBackend(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			addr := freeTestAddr(t)
			// No database: the remote lookup answers every login (proxy-only mode).
			srv, err := New(ctx, "localhost", addr, nil, POP3ProxyServerOptions{
				Name: "sasl-base64", RemoteAddrs: []string{backendAddr}, ConnectTimeout: 2 * time.Second,
				InsecureAuth:       true,
				MasterSASLUsername: "proxy-master", MasterSASLPassword: "proxy-master-secret",
				RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "2s"},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			go func() { _ = srv.Start() }()
			defer srv.Stop()

			conn, r := dialTest(t, addr)
			readLineWithPrefix(t, r, "+OK") // greeting
			if _, err := conn.Write([]byte(tc.send)); err != nil {
				t.Fatalf("send: %v", err)
			}
			if got := readLineWithPrefix(t, r, "+OK", "-ERR"); got != "-ERR Invalid SASL PLAIN response" {
				t.Fatalf("%q: reply %q, want -ERR Invalid SASL PLAIN response", tc.send, got)
			}
			select {
			case authzid := <-authzids:
				t.Fatalf("%q: the proxy logged in to the backend as %q", tc.send, authzid)
			default:
			}

			// The session is still not authenticated: the same credentials sent as
			// plain base64 log in on the same connection.
			if _, err := conn.Write([]byte("AUTH PLAIN " + plain + "\r\n")); err != nil {
				t.Fatalf("send: %v", err)
			}
			if got := readLineWithPrefix(t, r, "+OK", "-ERR"); !strings.HasPrefix(got, "+OK") {
				t.Fatalf("AUTH PLAIN after the refusal: reply %q, want +OK", got)
			}
			select {
			case authzid := <-authzids:
				if authzid != user {
					t.Errorf("the proxy logged in to the backend as %q, want %q", authzid, user)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the backend saw no AUTH PLAIN for the clean login")
			}
		})
	}
}
