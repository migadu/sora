package pop3proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"golang.org/x/crypto/bcrypt"
)

// startUTF8TestProxy starts a database-less POP3 proxy whose remote lookup answers
// every user with the bcrypt hash of password, routing to backendAddr. It returns
// the proxy's address and the number of lookups made.
func startUTF8TestProxy(t *testing.T, backendAddr, password string, remoteUseUTF8 bool) (string, *atomic.Int32) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	var lookups atomic.Int32
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"address": r.URL.Query().Get("email"), "password_hash": string(hash)})
	}))
	t.Cleanup(lookup.Close)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addr := freeTestAddr(t)
	srv, err := New(ctx, "localhost", addr, nil, POP3ProxyServerOptions{
		Name: "utf8-user", RemoteAddrs: []string{backendAddr}, ConnectTimeout: 2 * time.Second,
		InsecureAuth:       true,
		RemoteUseUTF8:      remoteUseUTF8,
		MasterSASLUsername: "proxy-master", MasterSASLPassword: "proxy-master-secret",
		RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "2s"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Stop() })
	return addr, &lookups
}

// readProxyCapa sends CAPA and returns the capability lines.
func readProxyCapa(t *testing.T, conn net.Conn, r *bufio.Reader) []string {
	t.Helper()
	fmt.Fprint(conn, "CAPA\r\n")
	readLineWithPrefix(t, r, "+OK")
	var caps []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("reading CAPA: %v", err)
		}
		if line = strings.TrimSpace(line); line == "." {
			return caps
		}
		caps = append(caps, line)
	}
}

// TestPOP3ProxyCAPAAdvertisesUTF8User: the proxy checks the credentials itself and
// accepts UTF-8 user names and passwords, so when it advertises UTF8 at all
// (remote_use_utf8) the capability carries the USER argument (RFC 6856 section 2.2:
// "Clients MUST NOT use UTF-8 characters when authenticating if the server did not
// include the USER argument in the UTF8 capability response"). Without
// remote_use_utf8, UTF8 stays hidden in every form (the Outlook post-auth UTF8
// incident). (#1934)
func TestPOP3ProxyCAPAAdvertisesUTF8User(t *testing.T) {
	for _, tc := range []struct {
		remoteUseUTF8 bool
		want          []string
	}{
		{true, []string{"UTF8 USER"}},
		{false, nil},
	} {
		t.Run(fmt.Sprintf("remote_use_utf8=%v", tc.remoteUseUTF8), func(t *testing.T) {
			addr, _ := startUTF8TestProxy(t, "127.0.0.1:110", "secret", tc.remoteUseUTF8)
			conn, r := dialTest(t, addr)
			readLineWithPrefix(t, r, "+OK") // greeting
			caps := readProxyCapa(t, conn, r)
			var got []string
			for _, c := range caps {
				if strings.EqualFold(strings.Fields(c)[0], "UTF8") {
					got = append(got, c)
				}
			}
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Fatalf("CAPA UTF8 lines = %q, want %q; full CAPA: %q", got, tc.want, caps)
			}
		})
	}
}

// TestPOP3ProxyLoginWithInvalidUTF8IsRefusedBeforeLookup: RFC 6856 section 2.2: "The
// server MUST reject UTF-8 usernames or passwords that fail to comply with the formal
// syntax in UTF-8 [RFC3629]." The proxy refuses such a USER/PASS login with the
// bad-credential reply and never asks the lookup about it. A client that did not send
// UTF8 and logs in with a valid UTF-8 password keeps working: section 2.2 restricts
// clients, and hashes are made from the UTF-8 bytes. (#1934)
func TestPOP3ProxyLoginWithInvalidUTF8IsRefusedBeforeLookup(t *testing.T) {
	const user, password = "user@example.com", "pässwörd"
	cases := []struct{ name, user, pass string }{
		{"password, Latin-1 a-umlaut", user, "p\xe4ssw\xf6rd"},
		{"password, stray continuation byte", user, "secret\x80"},
		{"user name, Latin-1 e-acute", "jos\xe9@example.com", password},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			backendAddr, authzids := authzidBackend(t)
			addr, lookups := startUTF8TestProxy(t, backendAddr, password, false)
			conn, r := dialTest(t, addr)
			readLineWithPrefix(t, r, "+OK") // greeting

			fmt.Fprintf(conn, "USER %s\r\n", tc.user)
			readLineWithPrefix(t, r, "+OK")
			fmt.Fprintf(conn, "PASS %s\r\n", tc.pass)
			if got := readLineWithPrefix(t, r, "+OK", "-ERR"); got != "-ERR [AUTH] Authentication failed" {
				t.Fatalf("PASS reply %q, want -ERR [AUTH] Authentication failed", got)
			}
			if n := lookups.Load(); n != 0 {
				t.Errorf("the remote lookup was asked %d times about malformed credentials", n)
			}
			select {
			case authzid := <-authzids:
				t.Fatalf("the proxy logged in to the backend as %q", authzid)
			default:
			}

			// Same connection, no UTF8 command: the UTF-8 password logs in.
			fmt.Fprintf(conn, "USER %s\r\n", user)
			readLineWithPrefix(t, r, "+OK")
			fmt.Fprintf(conn, "PASS %s\r\n", password)
			if got := readLineWithPrefix(t, r, "+OK", "-ERR"); !strings.HasPrefix(got, "+OK") {
				t.Fatalf("PASS with a valid UTF-8 password: reply %q, want +OK", got)
			}
			select {
			case authzid := <-authzids:
				if authzid != user {
					t.Errorf("the proxy logged in to the backend as %q, want %q", authzid, user)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the backend saw no login for the valid UTF-8 password")
			}
		})
	}
}
