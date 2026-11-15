package lmtpproxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// TestKickClosesLMTPSession drives the command loop of #1237: one LMTP
// connection delivers to two accounts, then one account is kicked through the
// proxy's tracker, as POST /admin/connections/kick does. The kick must close the
// session whichever of its recipients the account is, release every account the
// session counted, and leave a session that delivers to other accounts alone.
func TestKickClosesLMTPSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kick   string
		closed bool
	}{
		{name: "first recipient", kick: "first@example.com", closed: true},
		{name: "last recipient", kick: "second@example.com", closed: true},
		{name: "other account", kick: "other@example.com", closed: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
						io.WriteString(conn, "220 backend ready\r\n")
						reader := bufio.NewReader(conn)
						for {
							if _, err := reader.ReadString('\n'); err != nil {
								return
							}
							io.WriteString(conn, "250 OK\r\n")
						}
					}()
				}
			}()
			lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("email")})
			}))
			t.Cleanup(lookup.Close)
			srv, err := New(context.Background(), nil, "test-host", ServerOptions{
				Name: "kick", RemoteAddrs: []string{ln.Addr().String()}, RemotePort: 24, ConnectTimeout: time.Second,
				RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s"},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { srv.Stop() })
			tracker := server.NewConnectionTracker("LMTP", "", "", "test-instance", nil, 0, 0, 1000, false)
			t.Cleanup(tracker.Stop)
			srv.SetConnectionTracker(tracker)
			first := proxy.DeriveAccountIDFromEmail("first@example.com")
			second := proxy.DeriveAccountIDFromEmail("second@example.com")

			front, accepted := net.Pipe()
			t.Cleanup(func() { front.Close() })
			sess := newSession(srv, accepted, nil)
			done := make(chan struct{})
			go func() { defer close(done); sess.handleConnection() }()
			front.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(front)
			read := func() string {
				t.Helper()
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						t.Fatal(err)
					}
					if len(line) < 4 || line[3] != '-' {
						return strings.TrimSpace(line)
					}
				}
			}
			require := func(line, prefix string) {
				t.Helper()
				if _, err := fmt.Fprintf(front, "%s\r\n", line); err != nil {
					t.Fatal(err)
				}
				if resp := read(); !strings.HasPrefix(resp, prefix) {
					t.Fatalf("%s: %s, want %s", line, resp, prefix)
				}
			}
			if greeting := read(); !strings.HasPrefix(greeting, "220") {
				t.Fatal(greeting)
			}
			require("LHLO client.example.com", "250")
			require("MAIL FROM:<sender@example.com>", "250")
			require("RCPT TO:<first@example.com>", "250")
			require("RCPT TO:<second@example.com>", "250")

			if err := tracker.KickUser(proxy.DeriveAccountIDFromEmail(tc.kick), "LMTP"); err != nil {
				t.Fatalf("KickUser: %v", err)
			}

			finished := func() bool {
				select {
				case <-done:
					return true
				case <-time.After(3 * time.Second):
					return false
				}
			}
			if !tc.closed {
				require("NOOP", "250")
				require("QUIT", "221")
				if !finished() {
					t.Fatal("session did not finish after QUIT")
				}
				return
			}
			if !finished() {
				t.Fatalf("the LMTP session of %s is still open 3s after its kick", tc.kick)
			}
			if _, err := fmt.Fprint(front, "NOOP\r\n"); err == nil {
				if line, err := reader.ReadString('\n'); err == nil {
					t.Fatalf("NOOP after the kick answered %q, want the connection closed", line)
				}
			}
			if f, s := tracker.GetLocalConnectionCount(first), tracker.GetLocalConnectionCount(second); f != 0 || s != 0 {
				t.Fatalf("counts after the kick: first=%d second=%d, want 0 0", f, s)
			}
		})
	}
}
