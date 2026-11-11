//go:build integration

package pop3proxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/pop3proxy"
)

// recordingPOP3Backend is a minimal POP3 backend that accepts everything the proxy sends on
// the backend leg and records, per connection, the commands it received (verbs only).
type recordingPOP3Backend struct {
	ln       net.Listener
	mu       sync.Mutex
	sessions [][]string
}

func startRecordingPOP3Backend(t *testing.T) *recordingPOP3Backend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &recordingPOP3Backend{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			b.mu.Lock()
			b.sessions = append(b.sessions, nil)
			idx := len(b.sessions) - 1
			b.mu.Unlock()
			go b.serve(c, idx)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return b
}

func (b *recordingPOP3Backend) serve(c net.Conn, idx int) {
	defer c.Close()
	r := bufio.NewReader(c)
	fmt.Fprint(c, "+OK recording backend ready\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		verb := strings.ToUpper(strings.Fields(strings.TrimSpace(line) + " x")[0])
		b.mu.Lock()
		b.sessions[idx] = append(b.sessions[idx], verb)
		b.mu.Unlock()
		switch verb {
		case "STAT":
			fmt.Fprint(c, "+OK 0 0\r\n")
		case "QUIT":
			fmt.Fprint(c, "+OK bye\r\n")
			return
		default: // XCLIENT, UTF8, AUTH PLAIN <initial response>, ...
			fmt.Fprint(c, "+OK\r\n")
		}
	}
}

func (b *recordingPOP3Backend) addr() string { return b.ln.Addr().String() }

func (b *recordingPOP3Backend) session(i int) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if i >= len(b.sessions) {
		return nil
	}
	return append([]string(nil), b.sessions[i]...)
}

// countingListener accepts and immediately closes connections, counting them.
func countingListener(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), &n
}

// pinLookup answers every user with a hard pin ("server") to addr.
func pinLookup(t *testing.T, account common.TestAccount, addr string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"address": account.Email, "password_hash": string(hash), "server": addr})
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/lookup?email=$email"
}

// pop3Session logs in through the proxy, optionally asking for UTF8 first, then sends STAT
// and QUIT. It returns the PASS reply.
func pop3Session(t *testing.T, proxyAddr string, account common.TestAccount, utf8 bool) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(conn)
	read := func() string {
		line, _ := r.ReadString('\n')
		return strings.TrimSpace(line)
	}
	read() // greeting
	if utf8 {
		fmt.Fprint(conn, "UTF8\r\n")
		if resp := read(); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("UTF8: %q", resp)
		}
	}
	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	read()
	fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
	pass := read()
	if strings.HasPrefix(pass, "+OK") {
		fmt.Fprint(conn, "STAT\r\n")
		read()
		fmt.Fprint(conn, "QUIT\r\n")
		read()
	}
	return pass
}

func sawCommand(list []string, verb string) bool {
	for _, v := range list {
		if v == verb {
			return true
		}
	}
	return false
}

// TestPOP3ProxyCachedPinKeepsItsBackendSettings: a login served from the lookup cache must
// reach a pinned backend exactly as the uncached login did. The [remote_lookup] settings for
// the backend the lookup names (here: forward the client with XCLIENT, mirror UTF8) apply on
// every login, not only the first; and a cached pin whose backend has gone away still fails
// the login without ever connecting to another backend.
func TestPOP3ProxyCachedPinKeepsItsBackendSettings(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	pinned := startRecordingPOP3Backend(t)
	other, otherHits := countingListener(t)

	proxyAddr := common.GetRandomAddress(t)
	p, err := pop3proxy.New(context.Background(), "localhost", proxyAddr, rdb, pop3proxy.POP3ProxyServerOptions{
		Name:               "test-proxy-cached-pin",
		RemoteAddrs:        []string{other}, // the proxy's own list: never for a pinned user
		RemotePort:         110,
		MasterSASLUsername: "proxyuser",
		MasterSASLPassword: "proxypass",
		InsecureAuth:       true,
		ConnectTimeout:     3 * time.Second,
		AuthIdleTimeout:    time.Minute,
		AuthRateLimit:      server.AuthRateLimiterConfig{Enabled: false},
		TrustedProxies:     []string{"127.0.0.0/8", "::1/128"},
		LookupCache:        &config.LookupCacheConfig{Enabled: true, PositiveTTL: "5m", NegativeTTL: "1m", CleanupInterval: "1m", MaxSize: 100},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:          true,
			URL:              pinLookup(t, account, pinned.addr()),
			Timeout:          "5s",
			RemoteUseXCLIENT: true,
			RemoteUseUTF8:    true,
		},
	})
	if err != nil {
		t.Fatalf("pop3proxy.New: %v", err)
	}
	go func() { p.Start() }()
	t.Cleanup(func() { p.Stop() })
	time.Sleep(200 * time.Millisecond)

	for i, what := range []string{"uncached login", "login from the lookup cache"} {
		if resp := pop3Session(t, proxyAddr, account, true); !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("%s: PASS = %q", what, resp)
		}
		got := pinned.session(i)
		if !sawCommand(got, "XCLIENT") {
			t.Errorf("%s: the pinned backend got no XCLIENT (commands %v): the client's address was not forwarded", what, got)
		}
		if !sawCommand(got, "UTF8") {
			t.Errorf("%s: the pinned backend got no UTF8 (commands %v): it stays ASCII while the client was told UTF8", what, got)
		}
	}

	pinned.ln.Close() // the pinned backend goes away; the cache still names it
	if resp := pop3Session(t, proxyAddr, account, false); strings.HasPrefix(resp, "+OK") {
		t.Fatalf("login to a pinned backend that is gone succeeded: %q", resp)
	}
	time.Sleep(100 * time.Millisecond)
	if n := otherHits.Load(); n != 0 {
		t.Fatalf("the proxy connected %d time(s) to a backend the lookup did not name", n)
	}
}
