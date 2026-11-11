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
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/server/proxy"
	"golang.org/x/net/dns/dnsmessage"
)

// phase zero: a.test -> .1 and b.test -> .2. Phase one moves a.test
// to .3 and b.test to .1 atomically, without an overlapping ownership snapshot.
func lmtpPoolTransferDNS(t *testing.T) *atomic.Bool {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	phase := new(atomic.Bool)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, Authoritative: true, RecursionAvailable: true})
			b.StartQuestions()
			b.Question(q)
			b.StartAnswers()
			var last byte
			switch q.Name.String() {
			case "a.transfer.test.":
				if phase.Load() {
					last = 3
				} else {
					last = 1
				}
			case "b.transfer.test.":
				if phase.Load() {
					last = 1
				} else {
					last = 2
				}
			}
			if last != 0 && q.Type == dnsmessage.TypeA {
				b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, dnsmessage.AResource{A: [4]byte{127, 0, 0, last}})
			}
			response, err := b.Finish()
			if err == nil {
				conn.WriteTo(response, peer)
			}
		}
	}()
	old := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", conn.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = old; conn.Close(); <-done })
	return phase
}

type lmtpPoolCommand struct {
	connection int32
	command    string
}

// Exercise the real command loop: a held A connection cannot become a B connection
// just because DNS transfers its numeric destination. Between transactions a fresh
// connection is allowed; during a transaction accepted recipients must be preserved.
func TestLMTPHeldConnectionKeepsPoolIdentityAcrossDNSTransfer(t *testing.T) {
	for _, pin := range []bool{false, true} {
		for _, inTransaction := range []bool{false, true} {
			t.Run(fmt.Sprintf("pin=%v/in_transaction=%v", pin, inTransaction), func(t *testing.T) {
				phase := lmtpPoolTransferDNS(t)
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { ln.Close() })
				_, port, _ := net.SplitHostPort(ln.Addr().String())
				commands := make(chan lmtpPoolCommand, 32)
				var connections atomic.Int32
				go func() {
					for {
						conn, err := ln.Accept()
						if err != nil {
							return
						}
						id := connections.Add(1)
						go func() {
							defer conn.Close()
							conn.SetDeadline(time.Now().Add(10 * time.Second))
							io.WriteString(conn, "220 backend ready\r\n")
							reader := bufio.NewReader(conn)
							for {
								line, err := reader.ReadString('\n')
								if err != nil {
									return
								}
								if strings.HasPrefix(line, "RCPT ") {
									commands <- lmtpPoolCommand{id, strings.TrimSpace(line)}
								}
								io.WriteString(conn, "250 OK\r\n")
							}
						}()
					}
				}()
				lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					email := r.URL.Query().Get("email")
					pool := "a"
					if strings.HasPrefix(email, "b@") {
						pool = "b"
					}
					answer := map[string]any{"address": email, "pool": pool}
					if pin {
						answer["server"] = net.JoinHostPort("127.0.0.1", port)
						delete(answer, "pool")
					}
					json.NewEncoder(w).Encode(answer)
				}))
				t.Cleanup(lookup.Close)
				srv, err := New(context.Background(), nil, "test-host", ServerOptions{
					Name: "pool-reuse", RemotePort: 24, ConnectTimeout: time.Second,
					Pools: []proxy.PoolSpec{
						{Name: "a", Backends: []string{net.JoinHostPort("a.transfer.test", port)}},
						{Name: "b", Backends: []string{net.JoinHostPort("b.transfer.test", port)}},
					},
					RemoteLookup: &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "?email=$email", Timeout: "1s"},
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
				command := func(line string) string {
					t.Helper()
					if _, err := fmt.Fprintf(front, "%s\r\n", line); err != nil {
						t.Fatal(err)
					}
					return read()
				}
				require := func(line, prefix string) {
					t.Helper()
					if resp := command(line); !strings.HasPrefix(resp, prefix) {
						t.Fatalf("%s: %s, want %s", line, resp, prefix)
					}
				}
				if greeting := read(); !strings.HasPrefix(greeting, "220") {
					t.Fatal(greeting)
				}
				require("LHLO client", "250")
				require("MAIL FROM:<sender@example.com>", "250")
				require("RCPT TO:<a@example.com>", "250")
				first := <-commands
				// A same-pool recipient is a positive control: retain the existing socket.
				require("RCPT TO:<a2@example.com>", "250")
				if second := <-commands; second.connection != first.connection {
					t.Fatal("same-pool recipient did not reuse backend")
				}
				if !inTransaction {
					require("RSET", "250")
					require("MAIL FROM:<sender@example.com>", "250")
				}
				phase.Store(true)
				if err := srv.connManager.ResolveAddresses(); err != nil {
					t.Fatal(err)
				}
				if !srv.connManager.PoolHasBackend("b", ln.Addr().String()) || srv.connManager.PoolHasBackend("a", ln.Addr().String()) {
					t.Fatal("DNS did not transfer destination to B")
				}
				if inTransaction {
					if resp := command("RCPT TO:<b@example.com>"); !strings.HasPrefix(resp, "451") {
						t.Fatalf("B recipient reused held A socket: %s, want451", resp)
					}
					select {
					case leaked := <-commands:
						t.Fatalf("wrong-pool recipient reached held connection: %+v", leaked)
					default:
					}
					// Dropping a stale connection after acceptance must poison DATA too.
					require("DATA", "451")
				} else {
					require("RCPT TO:<b@example.com>", "250")
					if got := <-commands; got.connection == first.connection {
						t.Fatalf("new B transaction reused A connection %d", got.connection)
					}
				}
			})
		}
	}
}
