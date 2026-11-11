//go:build integration

package userapiproxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/userapi"
	"github.com/migadu/sora/server/userapiproxy"
)

// startProxyProtocolAPIBackend runs a User API backend that REQUIRES a PROXY protocol
// header on every connection.
func startProxyProtocolAPIBackend(t *testing.T, ctx context.Context, rdb *resilient.ResilientDatabase, name string) string {
	t.Helper()
	addr := common.GetRandomAddress(t)
	srv := userapi.Start(ctx, rdb, userapi.ServerOptions{
		Name:                        name,
		Addr:                        addr,
		JWTSecret:                   testJWTSecret,
		TokenDuration:               time.Hour,
		TokenIssuer:                 "test-issuer",
		AllowedOrigins:              []string{"*"},
		AllowedHosts:                []string{"127.0.0.1", "localhost"},
		ProxyProtocol:               true,
		ProxyProtocolTimeout:        "2s",
		ProxyProtocolTrustedProxies: []string{"127.0.0.1", "::1"},
	}, make(chan error, 1))
	if srv == nil {
		t.Fatalf("failed to start backend %s", name)
	}
	time.Sleep(150 * time.Millisecond)
	return addr
}

// TestUserAPIProxyPoolSettingsArePerPool: the PROXY protocol towards a backend is a per-pool
// setting of the User API proxy too. Two identical backends that both REQUIRE the header sit
// in two pools of one proxy; a login (routed by the email in its body) succeeds only through
// the pool whose block switches the header on, and swapping the blocks swaps which user gets in.
func TestUserAPIProxyPoolSettingsArePerPool(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backendA := startProxyProtocolAPIBackend(t, ctx, rdb, "api-backend-a")
	backendB := startProxyProtocolAPIBackend(t, ctx, rdb, "api-backend-b")

	stamp := time.Now().UnixNano()
	userA := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("api-settings-a-%d@example.com", stamp), "pw-a")
	userB := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("api-settings-b-%d@example.com", stamp), "pw-b")
	pools := map[string]string{userA.Email: "pool-a", userB.Email: "pool-b"}
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		pool, ok := pools[email]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"address": email, "pool": pool})
	}))
	defer lookup.Close()

	startProxy := func(headerForA, headerForB bool) string {
		addr := common.GetRandomAddress(t)
		p, err := userapiproxy.New(ctx, rdb, userapiproxy.ServerOptions{
			Name: "test-proxy-pool-settings",
			Addr: addr,
			Pools: []proxy.PoolSpec{
				{Name: "pool-a", Backends: []string{backendA}, Settings: proxy.BackendSettings{UseProxyProtocol: headerForA}},
				{Name: "pool-b", Backends: []string{backendB}, Settings: proxy.BackendSettings{UseProxyProtocol: headerForB}},
			},
			JWTSecret:      testJWTSecret,
			ConnectTimeout: 5 * time.Second,
			RemoteLookup:   &config.RemoteLookupConfig{Enabled: true, URL: lookup.URL + "/lookup?email=$email", Timeout: "5s"},
		})
		if err != nil {
			t.Fatalf("userapiproxy.New: %v", err)
		}
		go func() {
			if err := p.Start(); err != nil && ctx.Err() == nil {
				t.Logf("proxy: %v", err)
			}
		}()
		time.Sleep(100 * time.Millisecond)
		return addr
	}
	login := func(proxyAddr string, account common.TestAccount) int {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"email": account.Email, "password": account.Password})
		resp, err := (&http.Client{Timeout: 15 * time.Second}).Post("http://"+proxyAddr+"/user/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login %s: %v", account.Email, err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	proxyAB := startProxy(true, false)
	if status := login(proxyAB, userA); status != http.StatusOK {
		t.Fatalf("pool-a with the header on: %d, want 200", status)
	}
	if status := login(proxyAB, userB); status < 500 {
		t.Fatalf("pool-b with the header off: %d, want a 5xx (the backend refuses a connection without the header)", status)
	}

	proxyBA := startProxy(false, true)
	if status := login(proxyBA, userA); status < 500 {
		t.Fatalf("pool-a with the header off: %d, want a 5xx", status)
	}
	if status := login(proxyBA, userB); status != http.StatusOK {
		t.Fatalf("pool-b with the header on: %d, want 200", status)
	}
}
