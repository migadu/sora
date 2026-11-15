package imapproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// TestBackendFailureAfterLoginKeepsLiveSessionSlot: the proxy accepts the client's
// credentials before it reaches the backend, and registers the session with the
// connection tracker only once the backend has accepted the proxy's login. A session
// whose backend leg fails never held a slot, so its end must not release one: that
// would free the slot of the account's live session from the same client IP, letting
// the account exceed max_connections_per_user / max_connections_per_user_per_ip by
// one session per such failure (#796).
func TestBackendFailureAfterLoginKeepsLiveSessionSlot(t *testing.T) {
	const user, password = "user@example.com", "secret"
	for _, tc := range []struct {
		name    string
		backend func(t *testing.T) string
	}{
		{"backend down", deadIMAPBackendAddr},
		{"backend refuses the proxy login", refusingIMAPBackend},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			tracker := server.NewConnectionTracker("IMAP", "", "", "instance-1", nil, 0, 0, 1000, false)
			defer tracker.Stop()

			lookup := httptest.NewServer(acceptingIMAPLookup(t, password))
			defer lookup.Close()

			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := l.Addr().String()
			l.Close()
			srv, err := New(ctx, &resilient.ResilientDatabase{}, "localhost", ServerOptions{
				Name:               "unregistered",
				Addr:               addr,
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
			if err := tracker.RegisterConnection(ctx, accountID, user, "IMAP", "127.0.0.1:40000"); err != nil {
				t.Fatalf("register the live session: %v", err)
			}

			var conn net.Conn
			for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				if conn, err = net.Dial("tcp", addr); err == nil || time.Now().After(deadline) {
					break
				}
			}
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			r := bufio.NewReader(conn)
			if _, err := r.ReadString('\n'); err != nil {
				t.Fatalf("greeting: %v", err)
			}
			if _, err := conn.Write([]byte("a1 LOGIN " + user + " " + password + "\r\n")); err != nil {
				t.Fatal(err)
			}
			var reply string
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					t.Fatalf("LOGIN reply: %v", err)
				}
				if strings.HasPrefix(line, "a1 ") {
					reply = strings.TrimSpace(line)
					break
				}
			}
			if !strings.HasPrefix(reply, "a1 NO [UNAVAILABLE]") {
				t.Fatalf("LOGIN with a failing backend: %q, want a1 NO [UNAVAILABLE] ...", reply)
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

// acceptingIMAPLookup is a remote lookup that accepts password for any address and
// leaves the choice of backend to the proxy.
func acceptingIMAPLookup(t *testing.T, password string) http.HandlerFunc {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"address": r.URL.Query().Get("email"), "password_hash": string(hash)})
	}
}

// deadIMAPBackendAddr returns an address nothing listens on.
func deadIMAPBackendAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// refusingIMAPBackend serves IMAP connections that greet and then answer every
// command NO, so the proxy's master login is rejected.
func refusingIMAPBackend(t *testing.T) string {
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
				conn.Write([]byte("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready\r\n"))
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					tag, _, _ := strings.Cut(line, " ")
					conn.Write([]byte(tag + " NO [AUTHENTICATIONFAILED] Authentication failed\r\n"))
				}
			}()
		}
	}()
	return ln.Addr().String()
}
