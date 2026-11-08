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

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/pop3proxy"
	"github.com/migadu/sora/server/proxy"
	"golang.org/x/crypto/bcrypt"
)

// poolLookup is a remote-lookup API that answers with a pool name per user.
type poolLookup struct {
	mu    sync.Mutex
	pools map[string]string // email -> pool ("" = auth-only answer)
	hash  map[string]string // email -> password hash
	calls atomic.Int64      // lookups served (every status)
}

func newPoolLookup(t *testing.T) (*poolLookup, string) {
	t.Helper()
	l := &poolLookup{pools: map[string]string{}, hash: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.calls.Add(1)
		email := r.URL.Query().Get("email")
		l.mu.Lock()
		pool, known := l.pools[email]
		hash := l.hash[email]
		l.mu.Unlock()
		if !known {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		resp := map[string]any{"address": email, "password_hash": hash}
		if pool != "" {
			resp["pool"] = pool
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return l, srv.URL + "/lookup?email=$email"
}

func (l *poolLookup) add(t *testing.T, account common.TestAccount, pool string) {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	l.pools[account.Email] = pool
	l.hash[account.Email] = string(h)
	l.mu.Unlock()
}

func setupPOP3ProxyWithPools(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, pools []proxy.PoolSpec, lookupURL string, cache *config.LookupCacheConfig) *common.TestServer {
	t.Helper()
	opts := pop3proxy.POP3ProxyServerOptions{
		LookupCache:        cache,
		Name:               "test-proxy-pools",
		Pools:              pools,
		RemotePort:         110,
		MasterSASLUsername: "proxyuser",
		MasterSASLPassword: "proxypass",
		ConnectTimeout:     5 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		EnableAffinity:     true,
		AuthRateLimit:      server.AuthRateLimiterConfig{Enabled: false},
		TrustedProxies:     []string{"127.0.0.0/8", "::1/128"},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:          true,
			URL:              lookupURL,
			Timeout:          "5s",
			LookupLocalUsers: false,
		},
	}
	p, err := pop3proxy.New(context.Background(), "test-proxy-pools", proxyAddr, rdb, opts)
	if err != nil {
		t.Fatalf("pop3proxy.New: %v", err)
	}
	go func() {
		if err := p.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("POP3 proxy error: %v", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)
	return &common.TestServer{Address: proxyAddr, Server: &POP3ProxyWrapper{proxy: p, addr: proxyAddr, rdb: rdb}, ResilientDB: rdb}
}

func pop3Login(t *testing.T, proxyAddr string, account common.TestAccount) string {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(conn)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	fmt.Fprintf(conn, "USER %s\r\n", account.Email)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("USER: %v", err)
	}
	fmt.Fprintf(conn, "PASS %s\r\n", account.Password)
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("PASS: %v", err)
	}
	return strings.TrimSpace(line)
}

// TestPOP3ProxyPools: a lookup answer naming a pool is served by that pool only. A pool
// whose single member is dead refuses the login with a temporary error even though
// another pool's backend is alive, and an unknown pool name is refused the same way
// rather than reported as a wrong password.
func TestPOP3ProxyPools(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, _ := common.SetupPOP3ServerWithPROXY(t)
	defer backend.Close()
	rdb := backend.ResilientDB

	lookup, lookupURL := newPoolLookup(t)
	stamp := time.Now().UnixNano()
	live := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("pool-live-%d@example.com", stamp), "pw-live")
	dead := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("pool-dead-%d@example.com", stamp), "pw-dead")
	unknown := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("pool-unknown-%d@example.com", stamp), "pw-unknown")
	nopool := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("pool-none-%d@example.com", stamp), "pw-none")
	lookup.add(t, live, "sora-live")
	lookup.add(t, dead, "sora-dead")
	lookup.add(t, unknown, "sora-missing")
	lookup.add(t, nopool, "")

	pools := []proxy.PoolSpec{
		{Name: "sora-live", Backends: []string{backend.Address}, Settings: proxy.BackendSettings{UseProxyProtocol: true}},
		{Name: "sora-dead", Backends: []string{"127.0.0.1:1"}, Settings: proxy.BackendSettings{UseProxyProtocol: true}},
	}
	proxyAddr := common.GetRandomAddress(t)
	p := setupPOP3ProxyWithPools(t, rdb, proxyAddr, pools, lookupURL, nil)
	defer p.Close()

	if resp := pop3Login(t, proxyAddr, live); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("pool with a live member: login = %q, want +OK", resp)
	}
	for _, tc := range []struct {
		name    string
		account common.TestAccount
	}{
		{"pool whose only member is dead", dead},
		{"pool this proxy does not have", unknown},
		{"no pool named and no default", nopool},
	} {
		resp := pop3Login(t, proxyAddr, tc.account)
		if strings.HasPrefix(resp, "+OK") {
			t.Errorf("%s: login succeeded; the user was routed to another pool's backend", tc.name)
			continue
		}
		if !strings.Contains(resp, "SYS/TEMP") {
			t.Errorf("%s: %q, want a temporary failure ([SYS/TEMP]), not an auth failure", tc.name, resp)
		}
	}
}
