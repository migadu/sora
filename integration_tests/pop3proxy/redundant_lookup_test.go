//go:build integration

package pop3proxy_test

import (
	"context"
	"encoding/json"
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
)

// TestPOP3ProxySingleRemoteLookupOnDBFallback verifies that a cold (cache-miss)
// login of a DB-authenticated user hits the remotelookup endpoint exactly once.
// The lookup 404s the user, the proxy falls back to the main DB, and routing must
// not trigger a second round trip to the same endpoint for the same answer.
func TestPOP3ProxySingleRemoteLookupOnDBFallback(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupPOP3ServerWithPROXY(t)
	defer backendServer.Close()

	var calls atomic.Int32
	var mu sync.Mutex
	var urls []string
	remotelookupServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		mu.Lock()
		urls = append(urls, r.URL.String())
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "user not found"})
	}))
	defer remotelookupServer.Close()

	proxyAddress := common.GetRandomAddress(t)
	proxy := setupPOP3ProxyForRedundantLookupTest(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, remotelookupServer.URL)
	defer proxy.Stop()

	client, err := NewPOP3Client(proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to POP3 proxy: %v", err)
	}
	defer client.Close()

	if err := client.SendCommand("USER " + account.Email); err != nil {
		t.Fatalf("Failed to send USER: %v", err)
	}
	if resp, _ := client.ReadResponse(); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("USER command failed: %s", resp)
	}
	if err := client.SendCommand("PASS " + account.Password); err != nil {
		t.Fatalf("Failed to send PASS: %v", err)
	}
	resp, _ := client.ReadResponse()
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("Login should fall back to the main DB and succeed, got: %s", resp)
	}

	mu.Lock()
	seen := append([]string(nil), urls...)
	mu.Unlock()
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 remotelookup request for a cold DB-user login, got %d: %v", got, seen)
	}
	t.Logf("✓ single remotelookup request for cold DB-user login: %v", seen)
}

func setupPOP3ProxyForRedundantLookupTest(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, remotelookupURL string) *POP3ProxyWrapper {
	t.Helper()

	opts := pop3proxy.POP3ProxyServerOptions{
		Name:                   "test-pop3-proxy-redundant-lookup",
		RemoteAddrs:            backendAddrs,
		RemotePort:             110,
		MasterSASLUsername:     "proxyuser",
		MasterSASLPassword:     "proxypass",
		RemoteUseProxyProtocol: true,
		ConnectTimeout:         10 * time.Second,
		AuthIdleTimeout:        30 * time.Minute,
		EnableAffinity:         true,
		AuthRateLimit:          server.AuthRateLimiterConfig{Enabled: false},
		TrustedProxies:         []string{"127.0.0.0/8", "::1/128"},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled:          true,
			URL:              remotelookupURL + "/$email",
			Timeout:          "5s",
			LookupLocalUsers: true,
		},
		LookupCache: &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "5m",
			NegativeTTL:     "1m",
			MaxSize:         10000,
			CleanupInterval: "5m",
		},
	}

	proxy, err := pop3proxy.New(context.Background(), "test-host", proxyAddr, rdb, opts)
	if err != nil {
		t.Fatalf("Failed to create POP3 proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("POP3 proxy error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	return &POP3ProxyWrapper{
		proxy: proxy,
		addr:  proxyAddr,
		rdb:   rdb,
	}
}
