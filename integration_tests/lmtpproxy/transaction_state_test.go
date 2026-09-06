//go:build integration

package lmtpproxy_test

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
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtpproxy"
)

// These tests pin the proxy's transaction state machine: the MTA's view of a
// transaction (which recipients were accepted, which end-of-data reply belongs to which
// recipient, which transaction a command belongs to) must always be the backend's view.

// mockLMTPBackend is a scripted LMTP backend. dropOnRcpt makes the FIRST connection
// close without a reply on its Nth RCPT (a backend restart mid-transaction).
type mockLMTPBackend struct {
	conns      atomic.Int32
	rcpts      atomic.Int32
	mails      atomic.Int32
	dropOnRcpt int
}

func (m *mockLMTPBackend) serve(t *testing.T, l net.Listener) {
	t.Helper()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			n := m.conns.Add(1)
			go m.handle(c, n == 1)
		}
	}()
}

func (m *mockLMTPBackend) handle(c net.Conn, first bool) {
	defer c.Close()
	rd, wr := bufio.NewReader(c), bufio.NewWriter(c)
	wr.WriteString("220 mock LMTP ready\r\n")
	wr.Flush()
	accepted, rcptsThisConn := 0, 0
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		u := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(u, "LHLO"):
			wr.WriteString("250-mock\r\n250 PIPELINING\r\n")
		case strings.HasPrefix(u, "MAIL FROM"):
			m.mails.Add(1)
			accepted = 0
			wr.WriteString("250 Ok\r\n")
		case strings.HasPrefix(u, "RCPT TO"):
			m.rcpts.Add(1)
			rcptsThisConn++
			if first && m.dropOnRcpt > 0 && rcptsThisConn == m.dropOnRcpt {
				return // backend "restarts": connection dropped without a reply
			}
			accepted++
			wr.WriteString("250 Ok\r\n")
		case strings.HasPrefix(u, "DATA"):
			wr.WriteString("354 Go ahead\r\n")
			wr.Flush()
			for {
				b, err := rd.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(b, "\r\n") == "." {
					break
				}
			}
			for i := 0; i < accepted; i++ {
				wr.WriteString("250 2.0.0 Ok: queued\r\n")
			}
		case strings.HasPrefix(u, "RSET"):
			accepted = 0
			wr.WriteString("250 Ok\r\n")
		case strings.HasPrefix(u, "QUIT"):
			wr.WriteString("221 Bye\r\n")
			wr.Flush()
			return
		default:
			wr.WriteString("250 Ok\r\n")
		}
		wr.Flush()
	}
}

// startTransactionProxy starts a proxy whose remote lookup routes every recipient to
// backendAddr and counts the lookups it received.
func startTransactionProxy(t *testing.T, backendAddr string, lookups *atomic.Int32) (proxyAddr string) {
	t.Helper()
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"address": r.URL.Query().Get("q"), "server": backendAddr})
	}))
	t.Cleanup(lookup.Close)

	rdb := common.SetupTestDatabase(t)
	proxyAddr = common.GetRandomAddress(t)
	server, err := lmtpproxy.New(context.Background(), rdb, "localhost", lmtpproxy.ServerOptions{
		Name: "txn-state-proxy", Addr: proxyAddr, RemoteAddrs: []string{backendAddr}, RemotePort: 25,
		TrustedProxies:  []string{"127.0.0.0/8", "::1/128"},
		RemoteLookup:    &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?q=$email", Timeout: "5s", LookupLocalUsers: false},
		AuthIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	go server.Start()
	time.Sleep(150 * time.Millisecond)
	t.Cleanup(func() { server.Stop() })
	return proxyAddr
}

func listenMockBackend(t *testing.T, m *mockLMTPBackend) string {
	t.Helper()
	addr := common.GetRandomAddress(t)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	m.serve(t, l)
	return addr
}

// A backend lost after it accepted a recipient poisons the transaction: DATA (and any
// further RCPT) answer 451 so the MTA retries the whole message. A 503 here makes
// Postfix bounce the accepted recipient although no backend stored the message.
func TestLMTPProxy_BackendLostAfterAcceptedRcptDefersTransaction(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backend := &mockLMTPBackend{dropOnRcpt: 2}
	var lookups atomic.Int32
	proxyAddr := startTransactionProxy(t, listenMockBackend(t, backend), &lookups)

	client, err := NewLMTPClient(proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	send := func(cmd string) string {
		client.SendCommand(cmd)
		r, _ := client.ReadResponse()
		return r
	}
	client.SendCommand("LHLO mta.example")
	client.ReadMultilineResponse()
	if r := send("MAIL FROM:<sender@example.com>"); !strings.HasPrefix(r, "250") {
		t.Fatalf("MAIL: %s", r)
	}
	if r := send("RCPT TO:<r1@example.com>"); !strings.HasPrefix(r, "250") {
		t.Fatalf("RCPT r1: %s", r)
	}
	r2 := send("RCPT TO:<r2@example.com>")
	if !strings.HasPrefix(r2, "4") {
		t.Fatalf("RCPT r2 after backend drop: want 4xx, got %q", r2)
	}
	r3 := send("RCPT TO:<r3@example.com>")
	if !strings.HasPrefix(r3, "4") {
		t.Fatalf("RCPT r3 in a poisoned transaction: want 4xx (no silent reconnect), got %q", r3)
	}
	data := send("DATA")
	if !strings.HasPrefix(data, "4") {
		t.Fatalf("DATA after the backend was lost behind an accepted recipient: want 4xx, got %q", data)
	}
	if backend.conns.Load() != 1 {
		t.Fatalf("the proxy reconnected to the backend inside the poisoned transaction (%d connections)", backend.conns.Load())
	}

	// A new transaction is allowed to start over on a fresh backend connection.
	if r := send("RSET"); !strings.HasPrefix(r, "250") {
		t.Fatalf("RSET: %s", r)
	}
	if r := send("MAIL FROM:<sender@example.com>"); !strings.HasPrefix(r, "250") {
		t.Fatalf("MAIL (new transaction): %s", r)
	}
	if r := send("RCPT TO:<r4@example.com>"); !strings.HasPrefix(r, "250") {
		t.Fatalf("RCPT in the new transaction should reconnect and succeed, got %q", r)
	}
}

// After the first message, the connection returns to command mode: the second
// transaction is routed through the lookup like the first, its commands are forwarded
// and answered by the backend, and the end-of-data replies are relayed per recipient.
func TestLMTPProxy_SecondTransactionOnSameConnectionIsRouted(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	backend := &mockLMTPBackend{}
	var lookups atomic.Int32
	proxyAddr := startTransactionProxy(t, listenMockBackend(t, backend), &lookups)

	client, err := NewLMTPClient(proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	send := func(cmd string) string {
		client.SendCommand(cmd)
		r, _ := client.ReadResponse()
		return r
	}
	client.SendCommand("LHLO mta.example")
	client.ReadMultilineResponse()

	deliver := func(sender string, rcpts ...string) []string {
		if r := send(fmt.Sprintf("MAIL FROM:<%s>", sender)); !strings.HasPrefix(r, "250") {
			t.Fatalf("MAIL %s: %s", sender, r)
		}
		for _, rcpt := range rcpts {
			if r := send(fmt.Sprintf("RCPT TO:<%s>", rcpt)); !strings.HasPrefix(r, "250") {
				t.Fatalf("RCPT %s: %s", rcpt, r)
			}
		}
		if r := send("DATA"); !strings.HasPrefix(r, "354") {
			t.Fatalf("DATA: %s", r)
		}
		client.SendCommand("Subject: test\r\n\r\nbody\r\n.")
		var replies []string
		for range rcpts {
			r, err := client.ReadResponse()
			if err != nil {
				t.Fatalf("reading end-of-data reply: %v", err)
			}
			replies = append(replies, r)
		}
		return replies
	}

	first := deliver("a@example.com", "one@example.com")
	if len(first) != 1 || !strings.HasPrefix(first[0], "250") {
		t.Fatalf("first transaction end-of-data replies: %v", first)
	}
	lookupsAfterFirst := lookups.Load()

	// Second transaction on the same MTA connection, two recipients: it must be looked
	// up again (routing), reach the backend as MAIL/RCPT/DATA, and get two replies.
	second := deliver("b@example.com", "two@example.com", "three@example.com")
	if len(second) != 2 || !strings.HasPrefix(second[0], "250") || !strings.HasPrefix(second[1], "250") {
		t.Fatalf("second transaction end-of-data replies: %v", second)
	}
	if lookups.Load() <= lookupsAfterFirst {
		t.Fatalf("second transaction was not routed: lookups stayed at %d", lookupsAfterFirst)
	}
	if backend.mails.Load() != 2 || backend.rcpts.Load() != 3 {
		t.Fatalf("backend saw MAIL=%d RCPT=%d, want 2/3", backend.mails.Load(), backend.rcpts.Load())
	}
	// A third one still works (the connection is reusable indefinitely).
	if r := deliver("c@example.com", "four@example.com"); len(r) != 1 || !strings.HasPrefix(r[0], "250") {
		t.Fatalf("third transaction: %v", r)
	}
	if r := send("QUIT"); !strings.HasPrefix(r, "221") {
		t.Fatalf("QUIT: %s", r)
	}
}

// With user_not_found_response = "tempfail", every unknown-recipient RCPT answers 450 —
// the ones served from the negative lookup cache included.
func TestLMTPProxy_TempfailHonouredOnNegativeCacheHit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	lookupAddr := common.GetRandomAddress(t)
	ll, err := net.Listen("tcp", lookupAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer ll.Close()
	go func() {
		for {
			c, err := ll.Accept()
			if err != nil {
				return
			}
			go handleUserNotFoundLookup(c, "404")
		}
	}()

	rdb := common.SetupTestDatabase(t)
	proxyAddr := common.GetRandomAddress(t)
	server, err := lmtpproxy.New(context.Background(), rdb, "localhost", lmtpproxy.ServerOptions{
		Name: "tempfail-cache-proxy", Addr: proxyAddr, RemoteAddrs: []string{"backend.example.com:25"},
		TrustedProxies: []string{"127.0.0.0/8", "::1/128"},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled: true, URL: fmt.Sprintf("http://%s/lookup?email=$email", lookupAddr), Timeout: "5s",
			LookupLocalUsers: false, UserNotFoundResponse: "tempfail",
		},
		AuthIdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	go server.Start()
	time.Sleep(150 * time.Millisecond)
	defer server.Stop()

	client, err := NewLMTPClient(proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SendCommand("LHLO mta.example")
	client.ReadMultilineResponse()
	client.SendCommand("MAIL FROM:<sender@example.com>")
	client.ReadResponse()
	for i := 0; i < 3; i++ {
		client.SendCommand("RCPT TO:<unknown-cached@example.com>")
		r, _ := client.ReadResponse()
		if !strings.HasPrefix(r, "450") {
			t.Fatalf("RCPT #%d to an unknown user under tempfail: want 450, got %q", i+1, r)
		}
	}
}
