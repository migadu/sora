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
	"reflect"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/server/userapiproxy"
	"github.com/migadu/sora/testutils"
)

// TestUserAPIProxyPoolsLoginRateLimitIgnoresWhatTheLookupKnows (#895): with named pools
// and lookup_local_users off, wrong passwords for an address the lookup knows are
// answered by a backend of the user's pool, and those for an address it does not know by
// the proxy itself. With auth_rate_limit on the proxy both are counted and blocked
// alike: after max_attempts_per_ip_username failures, the next login for either address
// gets the same 401 as a wrong password, at once, without a password verification and
// without reaching a backend. The logins the proxy refused itself were never counted, so
// they kept costing a verification each while a known address was blocked, and the
// response time showed which addresses the lookup knows.
func TestUserAPIProxyPoolsLoginRateLimitIgnoresWhatTheLookupKnows(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)

	stamp := time.Now().UnixNano()
	known := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("api-limit-known-%d@example.com", stamp), "right-password")
	unknown := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("api-limit-unknown-%d@example.com", stamp), "right-password")

	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if email := r.URL.Query().Get("email"); email == known.Email {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"address": email, "pool": "pool-a"})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer lookup.Close()

	backend := newCountingBackend(t, rdb, "backend-a") // no rate limit of its own

	limit := config.DefaultAuthRateLimiterConfig()
	limit.Enabled = true
	limit.MaxAttemptsPerIPUsername = 3
	limit.DelayStartThreshold = 100 // no delays: this test is about the blocks

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr := common.GetRandomAddress(t)
	p, err := userapiproxy.New(ctx, rdb, userapiproxy.ServerOptions{
		Name:           "test-proxy-pools-rate-limit",
		Addr:           proxyAddr,
		Pools:          []proxy.PoolSpec{{Name: "pool-a", Backends: []string{backend.addr()}}},
		JWTSecret:      testJWTSecret,
		AllowedOrigins: []string{"*"},
		RemoteLookup: &config.RemoteLookupConfig{
			Enabled: true,
			URL:     lookup.URL + "/lookup?email=$email",
			Timeout: "5s",
		},
		AuthRateLimit: limit,
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

	type answer struct {
		status        int
		body          string
		header        http.Header
		verifications int
		reached       bool
	}
	client := &http.Client{Timeout: 10 * time.Second}
	login := func(email string) answer {
		t.Helper()
		raw, _ := json.Marshal(map[string]string{"email": email, "password": "wrong-password"})
		req, _ := http.NewRequest(http.MethodPost, "http://"+proxyAddr+"/user/auth/login", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://app.example.com")
		hits, before := backend.count.Load(), testutils.PasswordVerifications()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("login %s: %v", email, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		resp.Header.Del("Date")
		return answer{resp.StatusCode, string(body), resp.Header, testutils.PasswordVerifications() - before, backend.count.Load() > hits}
	}

	wrongPassword := login(known.Email)
	if wrongPassword.status != http.StatusUnauthorized || wrongPassword.verifications != 1 || !wrongPassword.reached {
		t.Fatalf("known address, wrong password: %+v; want a backend's 401 after one verification", wrongPassword)
	}
	for _, c := range []struct {
		name, email string
		known       bool
	}{
		{"address the lookup knows", known.Email, true},
		{"address the lookup does not know", unknown.Email, false},
	} {
		failures := 0
		if c.known {
			failures = 1 // wrongPassword
		}
		for ; failures < limit.MaxAttemptsPerIPUsername; failures++ {
			got := login(c.email)
			if got.status != wrongPassword.status || got.body != wrongPassword.body || got.verifications != 1 || got.reached != c.known {
				t.Errorf("%s, failure %d: %+v; want the wrong password's answer after one verification", c.name, failures+1, got)
			}
		}
		got := login(c.email)
		if got.status != wrongPassword.status || got.body != wrongPassword.body || !reflect.DeepEqual(got.header, wrongPassword.header) {
			t.Errorf("%s, blocked: %d %q %v; want the wrong password's %d %q %v",
				c.name, got.status, got.body, got.header, wrongPassword.status, wrongPassword.body, wrongPassword.header)
		}
		if got.verifications != 0 || got.reached {
			t.Errorf("%s, blocked: %d verifications, reached the backend %v; want neither", c.name, got.verifications, got.reached)
		}
	}
}
