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

// TestUserAPIProxyPoolsLoginRefusalLooksLikeWrongPassword: with named pools and
// lookup_local_users off, a login for an address the lookup does not know (404) or
// refuses (403) reaches no backend, and is answered exactly as a wrong password for an
// address the lookup knows, which a backend of the user's pool answers: the same status,
// body and headers, after one password verification. Both addresses have an account in
// the database the backend reads, which the backend would log in: the proxy must not
// send them there.
func TestUserAPIProxyPoolsLoginRefusalLooksLikeWrongPassword(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)

	stamp := time.Now().UnixNano()
	known := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("api-known-%d@example.com", stamp), "right-password")
	unknown := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("api-unknown-%d@example.com", stamp), "right-password")
	refused := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("api-refused-%d@example.com", stamp), "right-password")

	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch email := r.URL.Query().Get("email"); email {
		case known.Email:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"address": email, "pool": "pool-a"})
		case refused.Email:
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer lookup.Close()

	backend := newCountingBackend(t, rdb, "backend-a") // allowed_origins ["*"]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr := common.GetRandomAddress(t)
	p, err := userapiproxy.New(ctx, rdb, userapiproxy.ServerOptions{
		Name:           "test-proxy-pools-refusal",
		Addr:           proxyAddr,
		Pools:          []proxy.PoolSpec{{Name: "pool-a", Backends: []string{backend.addr()}}},
		JWTSecret:      testJWTSecret,
		AllowedOrigins: []string{"*"}, // the backends' list, as config.toml.example asks
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

	type answer struct {
		status        int
		body          string
		header        http.Header
		verifications int
	}
	client := &http.Client{Timeout: 10 * time.Second}
	login := func(email string) answer {
		t.Helper()
		raw, _ := json.Marshal(map[string]string{"email": email, "password": "wrong-password"})
		req, _ := http.NewRequest(http.MethodPost, "http://"+proxyAddr+"/user/auth/login", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://app.example.com")
		before := testutils.PasswordVerifications()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("login %s: %v", email, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		resp.Header.Del("Date")
		return answer{resp.StatusCode, string(body), resp.Header, testutils.PasswordVerifications() - before}
	}

	wrongPassword := login(known.Email)
	if wrongPassword.status != http.StatusUnauthorized || wrongPassword.verifications != 1 {
		t.Fatalf("known address, wrong password: %+v; want a backend's 401 after one verification", wrongPassword)
	}
	if n := backend.count.Load(); n != 1 {
		t.Fatalf("the wrong-password login reached the backend %d times, want once", n)
	}

	for _, c := range []struct{ name, email string }{
		{"lookup answers 404", unknown.Email},
		{"lookup answers 403", refused.Email},
	} {
		for i := 1; i <= 2; i++ {
			got := login(c.email)
			if got.status != wrongPassword.status || got.body != wrongPassword.body || got.verifications != wrongPassword.verifications {
				t.Errorf("%s, login %d: %d %q after %d verifications; want the wrong password's %d %q after %d",
					c.name, i, got.status, got.body, got.verifications, wrongPassword.status, wrongPassword.body, wrongPassword.verifications)
			}
			if !reflect.DeepEqual(got.header, wrongPassword.header) {
				t.Errorf("%s, login %d: headers %v; want the wrong password's %v", c.name, i, got.header, wrongPassword.header)
			}
		}
	}
	if n := backend.count.Load(); n != 1 {
		t.Errorf("logins the lookup refused reached the backend: it served %d requests, want 1", n)
	}
}
