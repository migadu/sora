//go:build integration

package userapi

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
	"github.com/migadu/sora/server/userapi"
)

// startLoginTestServer starts a User API on rdb, with the lookup cache when cached is set,
// and returns a function that posts one login and returns the status code.
func startLoginTestServer(t *testing.T, rdb *resilient.ResilientDatabase, cached bool) func(email, password string) int {
	t.Helper()
	opts := userapi.ServerOptions{
		Name:          fmt.Sprintf("test-userapi-login-%d", time.Now().UnixNano()),
		Addr:          "127.0.0.1:0",
		JWTSecret:     "test-secret-key-for-testing-only",
		TokenDuration: time.Hour,
		TokenIssuer:   "test-issuer",
	}
	if cached {
		cfg := config.DefaultLookupCacheConfig()
		opts.LookupCache = &cfg
	}
	srv, err := userapi.New(rdb, opts)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	testServer := httptest.NewServer(srv.SetupRoutes())
	t.Cleanup(testServer.Close)

	return func(email, password string) int {
		body, _ := json.Marshal(map[string]string{"email": email, "password": password})
		resp, err := testServer.Client().Post(testServer.URL+"/user/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login request failed: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
}

// TestUserAPILoginMalformedEmail: an email that is not an address is a failed login,
// 401, as on every other protocol, not 503: nothing is wrong with the database.
func TestUserAPILoginMalformedEmail(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	login := startLoginTestServer(t, common.SetupTestDatabase(t), false)

	if code := login("   ", "any-password"); code != http.StatusUnauthorized {
		t.Errorf("login with a blank email: %d, want %d", code, http.StatusUnauthorized)
	}
}

// TestUserAPILoginDeletedCachedAccount: a login answered from the lookup cache for an
// account deleted since it was cached is refused, 401, as the token refresh refuses
// it, not 503: the credential-epoch lookup found no active account, it did not fail.
func TestUserAPILoginDeletedCachedAccount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	login := startLoginTestServer(t, rdb, true)

	if code := login(account.Email, account.Password); code != http.StatusOK {
		t.Fatalf("first login: %d, want %d", code, http.StatusOK)
	}
	if err := rdb.DeleteAccountWithRetry(context.Background(), account.Email); err != nil {
		t.Fatalf("delete account: %v", err)
	}
	if code := login(account.Email, account.Password); code != http.StatusUnauthorized {
		t.Errorf("login after the account was deleted: %d, want %d", code, http.StatusUnauthorized)
	}
}
