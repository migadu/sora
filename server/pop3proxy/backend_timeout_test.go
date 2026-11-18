package pop3proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
)

// The proxy accepts the client's credentials (here from a fake remote lookup, so no
// database is needed) and only then logs in to the backend. A backend that stops
// answering during that leg must fail the login within about the connect timeout and
// be answered as a backend outage, -ERR [SYS/TEMP] (RFC 3206 section 4), never as
// [AUTH] "Authentication failed", which tells the client its password is wrong.

const backendTimeoutTestConnectTimeout = 500 * time.Millisecond

// stalledPOP3Backend serves connections that write greeting (nothing when empty), read
// the proxy's commands and never answer one, holding the connection open until the
// test ends.
func stalledPOP3Backend(t *testing.T, greeting string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		mu   sync.Mutex
		held []net.Conn
	)
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			c.Close()
		}
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn)
			mu.Unlock()
			go func() {
				if greeting != "" {
					conn.Write([]byte(greeting))
				}
				r := bufio.NewReader(conn)
				for {
					if _, err := r.ReadString('\n'); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// loginThroughProxy runs a proxy in front of backend whose remote lookup accepts
// user@example.com / secret, logs in with USER/PASS and returns the PASS reply and how
// long it took.
func loginThroughProxy(t *testing.T, backend string) (string, time.Duration) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	const user, password = "user@example.com", "secret"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"address": r.URL.Query().Get("email"), "password_hash": string(hash)})
	}))
	t.Cleanup(lookup.Close)

	addr := freeTestAddr(t)
	srv, err := New(ctx, "localhost", addr, &resilient.ResilientDatabase{}, POP3ProxyServerOptions{
		Name:               "backend-timeout",
		RemoteAddrs:        []string{backend},
		ConnectTimeout:     backendTimeoutTestConnectTimeout,
		InsecureAuth:       true,
		MasterSASLUsername: "proxy-master",
		MasterSASLPassword: "proxy-master-secret",
		RemoteLookup:       &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "5s"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	go func() { _ = srv.Start() }()
	t.Cleanup(func() { _ = srv.Stop() })

	conn, r := dialTest(t, addr) // 10s deadline: a proxy that waits on the backend forever fails the read below
	readLineWithPrefix(t, r, "+OK")
	conn.Write([]byte("USER " + user + "\r\n"))
	if reply := readLineWithPrefix(t, r, "+OK", "-ERR"); !strings.HasPrefix(reply, "+OK") {
		t.Fatalf("USER: %q", reply)
	}
	start := time.Now()
	conn.Write([]byte("PASS " + password + "\r\n"))
	reply := readLineWithPrefix(t, r, "+OK", "-ERR")
	return reply, time.Since(start)
}

func checkBackendTimeoutReply(t *testing.T, reply string, elapsed time.Duration) {
	t.Helper()
	const want = "-ERR [SYS/TEMP] Backend server temporarily unavailable"
	if reply != want {
		t.Errorf("PASS with a stalled backend: %q, want %q", reply, want)
	}
	if elapsed > 3*time.Second {
		t.Errorf("PASS with a stalled backend answered after %v, want within about the %v connect timeout", elapsed, backendTimeoutTestConnectTimeout)
	}
}

// TestBackendAuthTimeout: the backend greets, then never answers the proxy's AUTH PLAIN.
func TestBackendAuthTimeout(t *testing.T) {
	reply, elapsed := loginThroughProxy(t, stalledPOP3Backend(t, "+OK fake backend ready\r\n"))
	checkBackendTimeoutReply(t, reply, elapsed)
}

// TestBackendConnectTimeout: the backend accepts the TCP connection and never sends
// its greeting.
func TestBackendConnectTimeout(t *testing.T) {
	reply, elapsed := loginThroughProxy(t, stalledPOP3Backend(t, ""))
	checkBackendTimeoutReply(t, reply, elapsed)
}
