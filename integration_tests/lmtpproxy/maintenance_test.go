//go:build integration

package lmtpproxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtpproxy"
	"github.com/migadu/sora/server/proxy"
)

// countingBackend is a minimal LMTP backend that accepts every recipient and message and
// counts both.
type countingBackend struct {
	addr       string
	rcpts      atomic.Int32 // recipients accepted
	deliveries atomic.Int32 // messages received in full (end-of-data seen)
}

func startCountingBackend(t *testing.T, l net.Listener, name string) *countingBackend {
	t.Helper()
	b := &countingBackend{addr: l.Addr().String()}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go b.serve(conn, name)
		}
	}()
	return b
}

func (b *countingBackend) serve(c net.Conn, name string) {
	defer c.Close()
	rd := bufio.NewReader(c)
	fmt.Fprintf(c, "220 %s LMTP ready\r\n", name)
	accepted := 0 // recipients accepted in the current transaction
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		switch upper := strings.ToUpper(strings.TrimSpace(line)); {
		case strings.HasPrefix(upper, "LHLO"):
			fmt.Fprintf(c, "250-%s\r\n250-PIPELINING\r\n250 8BITMIME\r\n", name)
		case strings.HasPrefix(upper, "MAIL FROM"), strings.HasPrefix(upper, "RSET"):
			accepted = 0
			fmt.Fprint(c, "250 Ok\r\n")
		case strings.HasPrefix(upper, "RCPT TO"):
			accepted++
			b.rcpts.Add(1)
			fmt.Fprint(c, "250 Ok\r\n")
		case upper == "DATA":
			fmt.Fprint(c, "354 Go ahead\r\n")
			for {
				body, err := rd.ReadString('\n')
				if err != nil {
					return
				}
				if body == ".\r\n" || body == ".\n" {
					break
				}
			}
			b.deliveries.Add(1)
			for i := 0; i < accepted; i++ { // LMTP: one reply per accepted recipient
				fmt.Fprint(c, "250 2.0.0 Ok\r\n")
			}
			accepted = 0
		case strings.HasPrefix(upper, "NOOP"):
			fmt.Fprint(c, "250 Ok\r\n")
		case strings.HasPrefix(upper, "QUIT"):
			fmt.Fprint(c, "221 Bye\r\n")
			return
		default:
			fmt.Fprint(c, "500 Command unrecognized\r\n")
		}
	}
}

// maintenanceLMTP is an LMTP proxy over two backends on different hosts (maintenance is
// per host): backend1 on 127.0.0.1, backend2 on ::1. Remote lookup pins every recipient to
// backend1, so a recipient reaches backend2 only by being routed around maintenance.
type maintenanceLMTP struct {
	m                  *proxy.Maintenance
	backend1, backend2 *countingBackend
	proxyAddr          string
	client             *LMTPClient
}

func setupMaintenanceLMTP(t *testing.T) *maintenanceLMTP {
	t.Helper()
	common.SkipIfDatabaseUnavailable(t)

	l1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend1: %v", err)
	}
	t.Cleanup(func() { l1.Close() })
	l2, err := net.Listen("tcp", common.GetRandomIPv6LoopbackAddress(t))
	if err != nil {
		t.Fatalf("listen backend2: %v", err)
	}
	t.Cleanup(func() { l2.Close() })
	b1 := startCountingBackend(t, l1, "backend1")
	b2 := startCountingBackend(t, l2, "backend2")

	lookup := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"address": user, "server": b1.addr})
	})}
	lookupListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen lookup: %v", err)
	}
	go lookup.Serve(lookupListener)
	t.Cleanup(func() { lookup.Close() })

	rdb := common.SetupTestDatabase(t)
	proxyAddr := common.GetRandomAddress(t)
	srv, err := lmtpproxy.New(context.Background(), rdb, "localhost", lmtpproxy.ServerOptions{
		Name:           "test-proxy-maintenance",
		Addr:           proxyAddr,
		RemoteAddrs:    []string{b1.addr, b2.addr},
		RemotePort:     24,
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled: true,
			URL:     fmt.Sprintf("http://%s/lookup?q=$email", lookupListener.Addr()),
			Timeout: "5s",
		},
		AuthIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("create proxy: %v", err)
	}
	m := proxy.NewMaintenance()
	srv.GetConnectionManager().SetMaintenance(m)
	go srv.Start()
	t.Cleanup(func() { srv.Stop() })
	time.Sleep(100 * time.Millisecond)

	e := &maintenanceLMTP{m: m, backend1: b1, backend2: b2, proxyAddr: proxyAddr}
	e.reconnect(t)
	return e
}

// reconnect opens a new client connection to the proxy (closing the previous one) and
// sends LHLO, as a delivering MTA does for each message.
func (e *maintenanceLMTP) reconnect(t *testing.T) {
	t.Helper()
	if e.client != nil {
		e.client.SendCommand("QUIT")
		e.client.Close()
	}
	client, err := NewLMTPClient(e.proxyAddr)
	if err != nil {
		t.Fatalf("connect to proxy: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	client.SendCommand("LHLO localhost")
	client.ReadMultilineResponse()
	e.client = client
}

func (e *maintenanceLMTP) expect(t *testing.T, cmd, wantPrefix string) {
	t.Helper()
	if err := e.client.SendCommand(cmd); err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	resp, err := e.client.ReadResponse()
	if err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	if !strings.HasPrefix(resp, wantPrefix) {
		t.Fatalf("%s: got %q, want %s", cmd, resp, wantPrefix)
	}
}

func (e *maintenanceLMTP) recipients(t *testing.T, want1, want2 int32, when string) {
	t.Helper()
	if got1, got2 := e.backend1.rcpts.Load(), e.backend2.rcpts.Load(); got1 != want1 || got2 != want2 {
		t.Fatalf("%s: backend1=%d backend2=%d recipients, want %d and %d", when, got1, got2, want1, want2)
	}
}

// An MTA keeps its LMTP session open across messages: the session holds backend1, which
// goes into maintenance, and the next transaction must reach backend2 although the
// recipient's remote-lookup route names backend1.
func TestLMTPProxyBackendMaintenanceReroutesPinnedSession(t *testing.T) {
	e := setupMaintenanceLMTP(t)

	e.expect(t, "MAIL FROM:<sender@example.com>", "250")
	e.expect(t, "RCPT TO:<user1@example.com>", "250")
	e.expect(t, "RSET", "250")
	e.recipients(t, 1, 0, "before maintenance")

	e.m.Set([]string{"127.0.0.1"})

	e.expect(t, "MAIL FROM:<sender@example.com>", "250")
	e.expect(t, "RCPT TO:<user1@example.com>", "250")
	e.recipients(t, 1, 1, "in maintenance")
}

// Maintenance starting mid-transaction must not move it: backend1 already accepted a
// recipient, so dropping it would make the MTA retry the whole message (a duplicate for
// the accepted recipient). A further recipient routed elsewhere is refused for the MTA to
// retry alone; the message reaches backend1; the next transaction moves.
func TestLMTPProxyBackendMaintenanceNeverMovesATransaction(t *testing.T) {
	e := setupMaintenanceLMTP(t)

	e.expect(t, "MAIL FROM:<sender@example.com>", "250")
	e.expect(t, "RCPT TO:<user1@example.com>", "250")

	e.m.Set([]string{"127.0.0.1"})

	e.expect(t, "RCPT TO:<user2@example.com>", "451")
	e.expect(t, "DATA", "354")
	for _, line := range []string{"Subject: maintenance", "", "body"} {
		e.client.SendCommand(line)
	}
	e.expect(t, ".", "250")
	if got := e.backend1.deliveries.Load(); got != 1 {
		t.Fatalf("backend1 received %d messages, want 1 (the transaction it accepted)", got)
	}
	e.recipients(t, 1, 0, "after the transaction")

	e.expect(t, "MAIL FROM:<sender@example.com>", "250")
	e.expect(t, "RCPT TO:<user2@example.com>", "250")
	e.recipients(t, 1, 1, "next transaction")
}

// In and out of maintenance the way production delivers (strela: a fresh connection per
// message, one recipient): in maintenance the recipient's remote-lookup pin gives way to
// backend2; once maintenance ends a new connection reaches backend1 again.
func TestLMTPProxyBackendMaintenanceOnAndOffFreshConnections(t *testing.T) {
	e := setupMaintenanceLMTP(t)

	e.m.Set([]string{"127.0.0.1"})
	e.expect(t, "MAIL FROM:<sender@example.com>", "250")
	e.expect(t, "RCPT TO:<user1@example.com>", "250")
	e.recipients(t, 0, 1, "in maintenance")

	e.m.Set(nil)

	e.reconnect(t)
	e.expect(t, "MAIL FROM:<sender@example.com>", "250")
	e.expect(t, "RCPT TO:<user1@example.com>", "250")
	e.recipients(t, 1, 1, "after maintenance")
}
