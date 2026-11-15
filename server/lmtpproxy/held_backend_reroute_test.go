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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server/proxy"
)

// rerouteBackend is a minimal LMTP backend that records the envelope commands it
// receives, tagged with its name and connection number.
type rerouteBackend struct {
	name  string
	addr  string
	conns atomic.Int32
	mu    *sync.Mutex
	log   *[]string
}

func startRerouteBackend(t *testing.T, name string, mu *sync.Mutex, log *[]string) *rerouteBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	b := &rerouteBackend{name: name, addr: ln.Addr().String(), mu: mu, log: log}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			id := b.conns.Add(1)
			go b.serve(conn, id)
		}
	}()
	return b
}

func (b *rerouteBackend) record(id int32, line string) {
	b.mu.Lock()
	*b.log = append(*b.log, fmt.Sprintf("%s#%d %s", b.name, id, line))
	b.mu.Unlock()
}

func (b *rerouteBackend) serve(conn net.Conn, id int32) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	io.WriteString(conn, "220 "+b.name+" ready\r\n")
	reader := bufio.NewReader(conn)
	rcpts := 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		verb := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(verb, "LHLO"):
			io.WriteString(conn, "250-"+b.name+"\r\n250 PIPELINING\r\n")
		case strings.HasPrefix(verb, "MAIL"):
			rcpts = 0
			b.record(id, line)
			io.WriteString(conn, "250 2.1.0 Ok\r\n")
		case strings.HasPrefix(verb, "RCPT"):
			rcpts++
			b.record(id, line)
			io.WriteString(conn, "250 2.1.5 Ok\r\n")
		case verb == "DATA":
			b.record(id, line)
			io.WriteString(conn, "354 Go ahead\r\n")
			for {
				body, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if body == ".\r\n" {
					break
				}
			}
			for ; rcpts > 0; rcpts-- {
				io.WriteString(conn, "250 2.0.0 Delivered by "+b.name+"\r\n")
			}
		case verb == "RSET":
			rcpts = 0
			b.record(id, line)
			io.WriteString(conn, "250 2.0.0 Ok\r\n")
		case verb == "QUIT":
			io.WriteString(conn, "221 2.0.0 Bye\r\n")
			return
		default:
			io.WriteString(conn, "250 2.0.0 Ok\r\n")
		}
	}
}

// TestHeldBackendReroutesFirstRecipientOfTransaction drives the command loop of
// #1236: one LMTP connection the MTA keeps open delivers to a@example.com on
// backend A, then starts new transactions (after DATA, and after RSET) whose first
// recipient lives elsewhere. A transaction without an accepted recipient must be
// routed as on a fresh connection: the held backend is dropped and the proxy
// connects to the recipient's backend, re-sending MAIL FROM there. A later
// recipient of the same transaction that needs another backend still gets 451.
// Covered for a remote-lookup server pin (backend mismatch) and for named pools
// (pool mismatch).
func TestHeldBackendReroutesFirstRecipientOfTransaction(t *testing.T) {
	for _, routing := range []string{"server", "pool"} {
		t.Run("routing="+routing, func(t *testing.T) {
			var mu sync.Mutex
			var log []string
			a := startRerouteBackend(t, "A", &mu, &log)
			b := startRerouteBackend(t, "B", &mu, &log)
			lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				email := r.URL.Query().Get("email")
				answer := map[string]any{"address": email}
				backend, pool := a.addr, "a"
				if strings.HasPrefix(email, "b@") {
					backend, pool = b.addr, "b"
				}
				if routing == "server" {
					answer["server"] = backend
				} else {
					answer["pool"] = pool
				}
				json.NewEncoder(w).Encode(answer)
			}))
			t.Cleanup(lookup.Close)
			opts := ServerOptions{
				Name: "reroute", RemotePort: 24, ConnectTimeout: time.Second,
				RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s"},
			}
			if routing == "server" {
				opts.RemoteAddrs = []string{a.addr, b.addr}
			} else {
				opts.Pools = []proxy.PoolSpec{
					{Name: "a", Backends: []string{a.addr}},
					{Name: "b", Backends: []string{b.addr}},
				}
			}
			srv, err := New(context.Background(), nil, "test-host", opts)
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
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("session did not finish")
				}
			})
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

			// Transaction 1: a@example.com on A, delivered.
			require("MAIL FROM:<sender@example.com>", "250")
			require("RCPT TO:<a@example.com>", "250")
			require("DATA", "354")
			if _, err := io.WriteString(front, "Subject: one\r\n\r\nbody\r\n.\r\n"); err != nil {
				t.Fatal(err)
			}
			if resp := read(); !strings.HasPrefix(resp, "250") || !strings.Contains(resp, "by A") {
				t.Fatalf("end of data for a@: %s, want 250 from A", resp)
			}

			// Transaction 2, after DATA: the first recipient lives on B.
			require("MAIL FROM:<sender@example.com>", "250")
			require("RCPT TO:<b@example.com>", "250")
			// A later recipient of the same transaction on A cannot join B's.
			require("RCPT TO:<a@example.com>", "451")
			require("DATA", "354")
			if _, err := io.WriteString(front, "Subject: two\r\n\r\nbody\r\n.\r\n"); err != nil {
				t.Fatal(err)
			}
			if resp := read(); !strings.HasPrefix(resp, "250") || !strings.Contains(resp, "by B") {
				t.Fatalf("end of data for b@: %s, want 250 from B", resp)
			}

			// Transaction 3, after RSET: the first recipient lives on A again.
			require("MAIL FROM:<sender@example.com>", "250")
			require("RSET", "250")
			require("MAIL FROM:<other@example.com>", "250")
			require("RCPT TO:<a@example.com>", "250")
			require("QUIT", "221")
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("session did not finish after QUIT")
			}

			mu.Lock()
			got := strings.Join(log, "\n")
			mu.Unlock()
			want := strings.Join([]string{
				"A#1 MAIL FROM:<sender@example.com>",
				"A#1 RCPT TO:<a@example.com>",
				"A#1 DATA",
				"A#1 MAIL FROM:<sender@example.com>", // forwarded to the held A on MAIL
				"B#1 MAIL FROM:<sender@example.com>", // re-sent on the new B connection
				"B#1 RCPT TO:<b@example.com>",
				"B#1 DATA",
				"B#1 MAIL FROM:<sender@example.com>",
				"B#1 RSET",
				"B#1 MAIL FROM:<other@example.com>",
				"A#2 MAIL FROM:<other@example.com>",
				"A#2 RCPT TO:<a@example.com>",
			}, "\n")
			if got != want {
				t.Fatalf("backend commands:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}
