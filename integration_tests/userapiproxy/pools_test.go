//go:build integration

package userapiproxy_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/userapi"
	"github.com/migadu/sora/server/userapiproxy"
)

// countingBackend is a real User API backend that counts the requests it serves.
type countingBackend struct {
	srv   *httptest.Server
	count atomic.Int64
}

func newCountingBackend(t *testing.T, rdb *resilient.ResilientDatabase, name string) *countingBackend {
	t.Helper()
	api, err := userapi.New(rdb, userapi.ServerOptions{
		Name:           name,
		Addr:           "127.0.0.1:0",
		JWTSecret:      testJWTSecret,
		TokenDuration:  time.Hour,
		TokenIssuer:    "test-issuer",
		AllowedOrigins: []string{"*"},
		AllowedHosts:   []string{"127.0.0.1", "localhost"},
	})
	if err != nil {
		t.Fatalf("userapi.New(%s): %v", name, err)
	}
	b := &countingBackend{}
	routes := api.SetupRoutes()
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.count.Add(1)
		routes.ServeHTTP(w, r)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *countingBackend) addr() string { return b.srv.Listener.Addr().String() }

// TestUserAPIProxyPools: every request for a user — the login that names the user in its
// body, the token refresh, and the JWT-authenticated calls — reaches a backend of the
// pool the lookup named for that user, and no other. An unknown pool, or no pool for a
// user the lookup does not know, is refused.
func TestUserAPIProxyPools(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)

	stamp := time.Now().UnixNano()
	userA := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("api-a-%d@example.com", stamp), "pw-a")
	userB := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("api-b-%d@example.com", stamp), "pw-b")
	userX := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("api-x-%d@example.com", stamp), "pw-x")
	userNone := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("api-none-%d@example.com", stamp), "pw-none")

	var mu sync.Mutex
	pools := map[string]string{userA.Email: "pool-a", userB.Email: "pool-b", userX.Email: "pool-missing"}
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		mu.Lock()
		pool, known := pools[email]
		mu.Unlock()
		if !known {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"address": email, "pool": pool})
	}))
	defer lookup.Close()

	backendA := newCountingBackend(t, rdb, "backend-a")
	backendB := newCountingBackend(t, rdb, "backend-b")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr := common.GetRandomAddress(t)
	p, err := userapiproxy.New(ctx, rdb, userapiproxy.ServerOptions{
		Name: "test-proxy-pools",
		Addr: proxyAddr,
		Pools: []proxy.PoolSpec{
			{Name: "pool-a", Backends: []string{backendA.addr()}},
			{Name: "pool-b", Backends: []string{backendB.addr()}},
		},
		JWTSecret: testJWTSecret,
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled: true,
			URL:     lookup.URL + "/lookup?email=$email",
			Timeout: "5s",
		},
	})
	if err != nil {
		t.Fatalf("userapiproxy.New: %v", err)
	}
	go func() {
		if err := p.Start(); err != nil && ctx.Err() == nil {
			t.Logf("proxy error: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	client := &http.Client{Timeout: 10 * time.Second}
	post := func(path string, body any, token string) (*http.Response, []byte) {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, "http://"+proxyAddr+path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}
	get := func(path, token string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, "http://"+proxyAddr+path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp
	}
	login := func(account common.TestAccount) (int, string) {
		resp, body := post("/user/auth/login", map[string]string{"email": account.Email, "password": account.Password}, "")
		var out struct {
			Token string `json:"token"`
		}
		_ = json.Unmarshal(body, &out)
		return resp.StatusCode, out.Token
	}

	// User A: login (routed by the body), two authenticated calls, a refresh — all on A.
	status, tokenA := login(userA)
	if status != http.StatusOK || tokenA == "" {
		t.Fatalf("login A through the proxy = %d, token %q", status, tokenA)
	}
	for i := 0; i < 2; i++ {
		if resp := get("/user/mailboxes", tokenA); resp.StatusCode != http.StatusOK {
			t.Fatalf("mailboxes A = %d", resp.StatusCode)
		}
	}
	if resp, _ := post("/user/auth/refresh", map[string]string{"token": tokenA}, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh A = %d", resp.StatusCode)
	}
	if a, b := backendA.count.Load(), backendB.count.Load(); a != 4 || b != 0 {
		t.Fatalf("after user A: backend A served %d, B served %d; want 4 and 0", a, b)
	}

	// User B: the same path lands on B only.
	status, tokenB := login(userB)
	if status != http.StatusOK || tokenB == "" {
		t.Fatalf("login B through the proxy = %d", status)
	}
	if resp := get("/user/mailboxes", tokenB); resp.StatusCode != http.StatusOK {
		t.Fatalf("mailboxes B = %d", resp.StatusCode)
	}
	if a, b := backendA.count.Load(), backendB.count.Load(); a != 4 || b != 2 {
		t.Fatalf("after user B: backend A served %d, B served %d; want 4 and 2", a, b)
	}

	// A pool this proxy lacks, and a user the lookup does not know (no default pool):
	// refused, no backend touched.
	if status, _ := login(userX); status != http.StatusServiceUnavailable {
		t.Errorf("login for an unknown pool = %d, want 503", status)
	}
	if status, _ := login(userNone); status != http.StatusServiceUnavailable {
		t.Errorf("login for a user without a pool and no default = %d, want 503", status)
	}
	if a, b := backendA.count.Load(), backendB.count.Load(); a != 4 || b != 2 {
		t.Errorf("refused logins reached a backend: A %d, B %d", a, b)
	}

	// Moving a user between pools takes effect on the next lookup (no cache here).
	mu.Lock()
	pools[userA.Email] = "pool-b"
	mu.Unlock()
	if resp := get("/user/mailboxes", tokenA); resp.StatusCode != http.StatusOK {
		t.Fatalf("mailboxes A after move = %d", resp.StatusCode)
	}
	if a, b := backendA.count.Load(), backendB.count.Load(); a != 4 || b != 3 {
		t.Errorf("after moving A to pool-b: backend A served %d, B served %d; want 4 and 3", a, b)
	}
}
