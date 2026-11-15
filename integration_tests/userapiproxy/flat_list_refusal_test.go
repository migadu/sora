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
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/userapiproxy"
)

// TestUserAPIProxyFlatListRefusesWhatTheLookupRefuses (#911): a proxy with a flat
// remote_addrs list and lookup_local_users off, in front of a backend where every user
// has an account. While the lookup knows them, all of them log in and use their tokens.
// Once it refuses one (403, "the way to refuse an account") and no longer knows another
// (404), neither logs in with the right password, and their tokens are refused, without
// a request reaching the backend. The user it still knows is unaffected.
func TestUserAPIProxyFlatListRefusesWhatTheLookupRefuses(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)

	stamp := time.Now().UnixNano()
	known := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("api-flat-known-%d@example.com", stamp), "right-password")
	unknown := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("api-flat-unknown-%d@example.com", stamp), "right-password")
	refused := common.CreateTestAccountWithEmail(t, rdb, fmt.Sprintf("api-flat-refused-%d@example.com", stamp), "right-password")

	var mu sync.Mutex
	answers := map[string]int{known.Email: http.StatusOK, unknown.Email: http.StatusOK, refused.Email: http.StatusOK}
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email := r.URL.Query().Get("email")
		mu.Lock()
		status, ok := answers[email]
		mu.Unlock()
		if !ok {
			status = http.StatusNotFound
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		// Auth-only: no server, no pool, so the proxy picks from remote_addrs.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"address": email})
	}))
	defer lookup.Close()

	backend := newCountingBackend(t, rdb, "backend-flat")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	proxyAddr := common.GetRandomAddress(t)
	p, err := userapiproxy.New(ctx, rdb, userapiproxy.ServerOptions{
		Name:        "test-proxy-flat-refusal",
		Addr:        proxyAddr,
		RemoteAddrs: []string{backend.addr()},
		JWTSecret:   testJWTSecret,
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
	login := func(account common.TestAccount) (int, string, string) {
		t.Helper()
		raw, _ := json.Marshal(map[string]string{"email": account.Email, "password": account.Password})
		resp, err := client.Post("http://"+proxyAddr+"/user/auth/login", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("login %s: %v", account.Email, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var out struct {
			Token string `json:"token"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &out)
		return resp.StatusCode, out.Token, out.Error
	}
	mailboxes := func(token string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, "http://"+proxyAddr+"/user/mailboxes", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET /user/mailboxes: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode
	}

	tokens := map[string]string{}
	for _, account := range []common.TestAccount{known, unknown, refused} {
		status, token, _ := login(account)
		if status != http.StatusOK || token == "" {
			t.Fatalf("login %s while the lookup knows it = %d, token %q", account.Email, status, token)
		}
		if status := mailboxes(token); status != http.StatusOK {
			t.Fatalf("mailboxes %s while the lookup knows it = %d", account.Email, status)
		}
		tokens[account.Email] = token
	}
	served := backend.count.Load() // 6

	mu.Lock()
	answers[refused.Email] = http.StatusForbidden
	delete(answers, unknown.Email) // 404
	mu.Unlock()

	for _, c := range []struct {
		name    string
		account common.TestAccount
	}{
		{"lookup answers 403", refused},
		{"lookup answers 404", unknown},
	} {
		if status, token, msg := login(c.account); status != http.StatusUnauthorized || token != "" || msg != "Invalid credentials" {
			t.Errorf("%s: login with the right password = %d %q, token issued: %v; want 401 \"Invalid credentials\" and no token", c.name, status, msg, token != "")
		}
		if status := mailboxes(tokens[c.account.Email]); status != http.StatusServiceUnavailable {
			t.Errorf("%s: request with a token issued before = %d, want 503", c.name, status)
		}
	}
	if n := backend.count.Load() - served; n != 0 {
		t.Errorf("requests for users the lookup refuses reached the backend %d times, want never", n)
	}

	if status, token, _ := login(known); status != http.StatusOK || token == "" {
		t.Errorf("login %s, still known to the lookup = %d, token %q", known.Email, status, token)
	}
	if status := mailboxes(tokens[known.Email]); status != http.StatusOK {
		t.Errorf("mailboxes %s, still known to the lookup = %d", known.Email, status)
	}
}
