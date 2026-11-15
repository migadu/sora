package lmtpproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server/proxy"
)

// startFailFirstBackend starts an LMTP backend whose first connection fails at
// failAt ("greeting", "LHLO", "XCLIENT" or "MAIL": a 421 greeting, a 421 to LHLO, or
// the connection closed without a reply to XCLIENT or MAIL) and whose later
// connections accept everything. It returns its address and its connection count.
func startFailFirstBackend(t *testing.T, failAt string) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var conns atomic.Int32
	serve := func(conn net.Conn, fail bool) {
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if fail && failAt == "greeting" {
			io.WriteString(conn, "421 4.3.2 Not ready\r\n")
			return
		}
		io.WriteString(conn, "220 backend ready\r\n")
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			verb, _, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
			verb = strings.ToUpper(verb)
			if fail && verb == failAt {
				if verb == "LHLO" {
					io.WriteString(conn, "421 4.3.2 Busy\r\n")
				}
				return
			}
			switch verb {
			case "LHLO":
				io.WriteString(conn, "250-backend\r\n250 PIPELINING\r\n")
			case "QUIT":
				io.WriteString(conn, "221 bye\r\n")
				return
			default:
				io.WriteString(conn, "250 2.0.0 OK\r\n")
			}
		}
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serve(conn, conns.Add(1) == 1)
		}
	}()
	return ln.Addr().String(), &conns
}

// TestFailedBackendConnectIsNotHeld covers #1186: a backend connection that fails
// after it was dialed (greeting, LHLO, XCLIENT exchange, MAIL FROM) must not stay held
// by the session. The next recipient connects afresh instead of being sent to the
// closed connection (451 4.4.2 without a connect attempt), and a DATA with no
// recipient accepted is a bad sequence (503), not a backend error.
func TestFailedBackendConnectIsNotHeld(t *testing.T) {
	for _, failAt := range []string{"greeting", "LHLO", "XCLIENT", "MAIL"} {
		for _, next := range []string{"RCPT", "DATA"} {
			t.Run(failAt+"/"+next, func(t *testing.T) {
				addr, conns := startFailFirstBackend(t, failAt)
				lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
				}))
				t.Cleanup(lookup.Close)
				srv, err := New(context.Background(), nil, "test-host", ServerOptions{
					Name: "failed-connect", RemoteAddrs: []string{addr}, RemotePort: 24, ConnectTimeout: time.Second,
					RemoteUseXCLIENT: true,
					RemoteLookup:     &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s"},
				})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { srv.Stop() })

				front, accepted := net.Pipe()
				sess := newSession(srv, accepted, nil)
				done := make(chan struct{})
				go func() { defer close(done); sess.handleConnection() }()
				t.Cleanup(func() {
					front.Close()
					<-done
				})
				front.SetDeadline(time.Now().Add(10 * time.Second))
				reader := bufio.NewReader(front)
				if greeting := readReply(t, reader); !strings.HasPrefix(greeting, "220 ") {
					t.Fatalf("greeting = %q", greeting)
				}
				step := func(cmd, want string, wantConns int32) {
					t.Helper()
					if _, err := io.WriteString(front, cmd+"\r\n"); err != nil {
						t.Fatal(err)
					}
					got := readReply(t, reader)
					if !strings.HasPrefix(got, want) {
						t.Errorf("%s: %q, want %q", cmd, got, want)
					}
					if n := conns.Load(); n != wantConns {
						t.Errorf("%s: %d backend connections, want %d", cmd, n, wantConns)
					}
				}
				step("LHLO client.example.org", "250 ", 0)
				step("MAIL FROM:<sender@example.com>", "250 ", 0)
				step("RCPT TO:<a@example.com>", "451 4.4.1 ", 1)
				if next == "DATA" {
					step("DATA", "503 5.5.1 ", 1)
				}
				step("RCPT TO:<a2@example.com>", "250 ", 2)
			})
		}
	}
}

// TestFailedSTARTTLSConnectIsNotHeld covers the STARTTLS steps of #1186, before and
// after the TLS connection replaced the plaintext one: connectToBackend fails, the
// session holds no backend connection or route, and the backend sees the connection
// closed.
func TestFailedSTARTTLSConnectIsNotHeld(t *testing.T) {
	const ready = "220 2.0.0 ready to start TLS\r\n"
	for _, tc := range []struct {
		name    string
		backend fakeLMTPBackend
	}{
		{"STARTTLS refused", fakeLMTPBackend{}},
		{"data after the STARTTLS reply", fakeLMTPBackend{startTLSReply: ready + "250 injected\r\n"}},
		{"TLS handshake", fakeLMTPBackend{startTLSReply: ready, noHandshake: true}},
		{"LHLO after STARTTLS", fakeLMTPBackend{startTLSReply: ready, lhloAfterTLS: "421 4.3.2 Busy\r\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, commands := tc.backend.start(t)
			sess, err := connectLMTPBackend(t, addr, proxy.BackendSettings{TLS: true, TLSUseStartTLS: true}, nil, 500*time.Millisecond)
			if err == nil {
				t.Fatal("connectToBackend succeeded")
			}
			if sess.backendConn != nil || sess.backendRoute != nil {
				t.Errorf("after %q the session holds backendConn %T, backendRoute %v; want neither", err, sess.backendConn, sess.backendRoute)
			}
			// The fake backend also ends the connection on its own 10 s deadline, so
			// only a prompt end shows that connectToBackend closed it.
			waitStart := time.Now()
			commands()
			if waited := time.Since(waitStart); waited > 2*time.Second {
				t.Errorf("the backend saw its connection end %v after connectToBackend failed (its own deadline): the connection was left open", waited.Round(time.Second))
			}
		})
	}
}
