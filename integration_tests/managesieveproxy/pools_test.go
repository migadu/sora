//go:build integration

package managesieveproxy_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	"github.com/migadu/sora/server/managesieveproxy"
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

func setupManageSieveProxyWithPools(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, pools []proxy.PoolSpec, lookupURL string, cache *config.LookupCacheConfig) *common.TestServer {
	t.Helper()
	opts := managesieveproxy.ServerOptions{
		LookupCache:        cache,
		Name:               "test-proxy-pools",
		Addr:               proxyAddr,
		Pools:              pools,
		RemotePort:         4190,
		MasterSASLUsername: "master_sasl",
		MasterSASLPassword: "master_sasl_secret",
		InsecureAuth:       true,
		ConnectTimeout:     5 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		CommandTimeout:     5 * time.Minute,
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
	p, err := managesieveproxy.New(context.Background(), rdb, "test-proxy-pools", opts)
	if err != nil {
		t.Fatalf("managesieveproxy.New: %v", err)
	}
	go func() {
		if err := p.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("ManageSieve proxy error: %v", err)
		}
	}()
	time.Sleep(200 * time.Millisecond)
	return &common.TestServer{Address: proxyAddr, Server: p, ResilientDB: rdb}
}

func sieveAuth(t *testing.T, proxyAddr string, account common.TestAccount) string {
	t.Helper()
	client, err := NewManageSieveClient(proxyAddr)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)))
	if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", auth)); err != nil {
		t.Fatalf("AUTHENTICATE: %v", err)
	}
	resp, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("AUTHENTICATE response: %v", err)
	}
	return resp
}

// TestManageSieveProxyPools: a lookup answer naming a pool is served by that pool only;
// a dead pool, an unknown pool and an answer without a pool (no default) are refused
// without touching the live pool's backend.
func TestManageSieveProxyPools(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backend, _ := common.SetupManageSieveServerWithMaster(t)
	defer backend.Close()
	rdb := backend.ResilientDB

	lookup, lookupURL := newPoolLookup(t)
	stamp := time.Now().UnixNano()
	live := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("sieve-live-%d@example.com", stamp), "pw-live")
	dead := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("sieve-dead-%d@example.com", stamp), "pw-dead")
	unknown := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("sieve-unknown-%d@example.com", stamp), "pw-unknown")
	nopool := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("sieve-none-%d@example.com", stamp), "pw-none")
	lookup.add(t, live, "sora-live")
	lookup.add(t, dead, "sora-dead")
	lookup.add(t, unknown, "sora-missing")
	lookup.add(t, nopool, "")

	pools := []proxy.PoolSpec{
		// This backend speaks plain ManageSieve (no PROXY header), so the pool says so.
		{Name: "sora-live", Backends: []string{backend.Address}},
		{Name: "sora-dead", Backends: []string{"127.0.0.1:1"}},
	}
	proxyAddr := common.GetRandomAddress(t)
	p := setupManageSieveProxyWithPools(t, rdb, proxyAddr, pools, lookupURL, nil)
	defer p.Close()

	if resp := sieveAuth(t, proxyAddr, live); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("pool with a live member: AUTHENTICATE = %q, want OK", resp)
	}
	for _, tc := range []struct {
		name    string
		account common.TestAccount
	}{
		{"pool whose only member is dead", dead},
		{"pool this proxy does not have", unknown},
		{"no pool named and no default", nopool},
	} {
		resp := sieveAuth(t, proxyAddr, tc.account)
		if strings.HasPrefix(resp, "OK") {
			t.Errorf("%s: AUTHENTICATE succeeded; the user was routed to another pool's backend", tc.name)
			continue
		}
		if !strings.HasPrefix(resp, "NO") {
			t.Errorf("%s: %q, want NO", tc.name, resp)
		}
	}
}
