package pop3proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// TestPOP3BackendFailureAfterLoginKeepsLiveSessionSlot: the proxy accepts the client's
// credentials before it reaches the backend, and registers the session with the
// connection tracker only once the backend has accepted the proxy's login. A session
// whose backend leg fails never held a slot, so its end must not release one: that
// would free the slot of the account's live session from the same client IP, letting
// the account exceed max_connections_per_user / max_connections_per_user_per_ip by
// one session per such failure (#796).
func TestPOP3BackendFailureAfterLoginKeepsLiveSessionSlot(t *testing.T) {
	const user, password = "user@example.com", "secret"
	for _, tc := range []struct {
		name    string
		backend func(t *testing.T) string
	}{
		{"backend down", freeTestAddr},
		{"backend refuses the proxy login", refusingPOP3Backend},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			tracker := server.NewConnectionTracker("POP3", "", "", "instance-1", nil, 0, 0, 1000, false)
			defer tracker.Stop()

			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
			if err != nil {
				t.Fatal(err)
			}
			lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"address": r.URL.Query().Get("email"), "password_hash": string(hash)})
			}))
			defer lookup.Close()

			addr := freeTestAddr(t)
			srv, err := New(ctx, "localhost", addr, &resilient.ResilientDatabase{}, POP3ProxyServerOptions{
				Name:               "unregistered",
				RemoteAddrs:        []string{tc.backend(t)},
				ConnectTimeout:     2 * time.Second,
				InsecureAuth:       true,
				MasterSASLUsername: "proxy-master",
				MasterSASLPassword: "proxy-master-secret",
				RemoteLookup:       &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "5s"},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			srv.SetConnectionTracker(tracker)
			go func() { _ = srv.Start() }()
			defer srv.Stop()

			// The account's live session from the same client IP on this listener.
			accountID := proxy.DeriveAccountIDFromEmail(user)
			if err := tracker.RegisterConnection(ctx, accountID, user, "POP3", "127.0.0.1:40000"); err != nil {
				t.Fatalf("register the live session: %v", err)
			}

			conn, r := dialTest(t, addr)
			readLineWithPrefix(t, r, "+OK")
			conn.Write([]byte("USER " + user + "\r\n"))
			readLineWithPrefix(t, r, "+OK", "-ERR")
			conn.Write([]byte("PASS " + password + "\r\n"))
			if reply := readLineWithPrefix(t, r, "+OK", "-ERR"); reply != "-ERR [SYS/TEMP] Backend server temporarily unavailable" {
				t.Fatalf("PASS with a failing backend: %q, want -ERR [SYS/TEMP] Backend server temporarily unavailable", reply)
			}
			conn.Close()

			// Wait for the failed session to end, close() included.
			if !srv.sessions.Drain(5 * time.Second) {
				t.Fatal("the failed session did not end")
			}

			if got := tracker.GetLocalConnectionCount(accountID); got != 1 {
				t.Errorf("connection count = %d after a session whose backend leg failed ended, want 1 (the live session's slot)", got)
			}
		})
	}
}

// refusingPOP3Backend serves POP3 connections that greet and then answer every
// command -ERR, so the proxy's master login is rejected.
func refusingPOP3Backend(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				conn.Write([]byte("+OK ready\r\n"))
				r := bufio.NewReader(conn)
				for {
					if _, err := r.ReadString('\n'); err != nil {
						return
					}
					conn.Write([]byte("-ERR [AUTH] Authentication failed\r\n"))
				}
			}()
		}
	}()
	return ln.Addr().String()
}
