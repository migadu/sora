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
)

// TestManageSieveProxySingleRemoteLookupOnDBFallback verifies that a cold
// (cache-miss) login of a DB-authenticated user hits the remotelookup endpoint
// exactly once. The lookup 404s the user, the proxy falls back to the main DB,
// and routing must not trigger a second round trip to the same answer.
func TestManageSieveProxySingleRemoteLookupOnDBFallback(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	backendServer, account := common.SetupManageSieveServerWithMaster(t)
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
	proxy := setupManageSieveProxyForRedundantLookupTest(t, backendServer.ResilientDB, proxyAddress, []string{backendServer.Address}, remotelookupServer.URL)
	defer proxy.Close()

	client, err := NewManageSieveClient(proxyAddress)
	if err != nil {
		t.Fatalf("Failed to connect to ManageSieve proxy: %v", err)
	}
	defer client.Close()

	authString := fmt.Sprintf("\x00%s\x00%s", account.Email, account.Password)
	authBase64 := base64.StdEncoding.EncodeToString([]byte(authString))
	if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", authBase64)); err != nil {
		t.Fatalf("Failed to send AUTHENTICATE command: %v", err)
	}
	response, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("Failed to read AUTHENTICATE response: %v", err)
	}
	if !strings.HasPrefix(response, "OK") {
		t.Fatalf("Authentication should fall back to the main DB and succeed, got: %s", response)
	}

	mu.Lock()
	seen := append([]string(nil), urls...)
	mu.Unlock()
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 remotelookup request for a cold DB-user login, got %d: %v", got, seen)
	}
	t.Logf("✓ single remotelookup request for cold DB-user login: %v", seen)
}

func setupManageSieveProxyForRedundantLookupTest(t *testing.T, rdb *resilient.ResilientDatabase, proxyAddr string, backendAddrs []string, remotelookupURL string) *common.TestServer {
	t.Helper()

	opts := managesieveproxy.ServerOptions{
		Name:               "test-managesieve-proxy-redundant-lookup",
		Addr:               proxyAddr,
		RemoteAddrs:        backendAddrs,
		RemotePort:         4190,
		MasterSASLUsername: "master_sasl",
		MasterSASLPassword: "master_sasl_secret",
		InsecureAuth:       true,
		ConnectTimeout:     10 * time.Second,
		AuthIdleTimeout:    30 * time.Minute,
		CommandTimeout:     5 * time.Minute,
		EnableAffinity:     true,
		AuthRateLimit:      server.AuthRateLimiterConfig{Enabled: false},
		TrustedProxies:     []string{"127.0.0.0/8", "::1/128"},
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

	proxy, err := managesieveproxy.New(context.Background(), rdb, "test-host", opts)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve proxy: %v", err)
	}

	go func() {
		if err := proxy.Start(); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			t.Logf("ManageSieve proxy error: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)

	return &common.TestServer{
		Address:     proxyAddr,
		Server:      proxy,
		ResilientDB: rdb,
	}
}
