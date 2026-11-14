//go:build integration

package userapi

import (
	"bytes"
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

// startUserAPIWithLookupCache starts a User API that blocks a user after two failed
// logins (common.DBOutageAuthRateLimit) and returns its login function, which
// answers the status code. lookupCache nil runs without a lookup cache.
func startUserAPIWithLookupCache(t *testing.T, rdb *resilient.ResilientDatabase, lookupCache *config.LookupCacheConfig) (login func(email, password string) int) {
	t.Helper()

	srv, err := userapi.New(rdb, userapi.ServerOptions{
		Name:          fmt.Sprintf("test-userapi-unverifiable-hash-%d", time.Now().UnixNano()),
		Addr:          "127.0.0.1:0",
		JWTSecret:     "test-secret-key-for-testing-only",
		TokenDuration: time.Hour,
		TokenIssuer:   "test-issuer",
		AuthRateLimit: common.DBOutageAuthRateLimit(),
		LookupCache:   lookupCache,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	testServer := httptest.NewServer(srv.SetupRoutes())
	t.Cleanup(testServer.Close)

	return func(email, password string) int {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"email": email, "password": password})
		resp, err := testServer.Client().Post(testServer.URL+"/user/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login request failed: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
}

// TestUserAPILoginWithUnverifiableStoredHash: a stored hash sora cannot check says
// nothing about the submitted password, and only an administrator can repair it. The
// login is answered 503 Service Unavailable, as for a database outage (RFC 9110
// section 15.6.4), logged with the address and the reason unverifiable_hash, and not
// counted by the auth rate limiter: the user logs in as soon as the hash is repaired.
func TestUserAPILoginWithUnverifiableStoredHash(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	login := startUserAPIWithLookupCache(t, rdb, nil)
	logs := common.CaptureLogs(t)

	repair := common.StoreUnverifiableHash(t, rdb, account.Email, account.Password)
	for i := 1; i <= 3; i++ {
		if code := login(account.Email, account.Password); code != http.StatusServiceUnavailable {
			t.Errorf("login %d against an unverifiable stored hash: %d, want %d", i, code, http.StatusServiceUnavailable)
		}
	}
	repair()

	if code := login(account.Email, account.Password); code != http.StatusOK {
		t.Errorf("login after the hash was repaired: %d, want %d (the unverifiable hash was counted as failed logins)", code, http.StatusOK)
	}
	logs.WaitForLine(t, "authentication unavailable", account.Email, "reason=unverifiable_hash")
}

// TestUserAPIUnverifiableStoredHashDropsCachedLogin: a login in the lookup cache was
// verified against the hash stored before. A guess that misses it goes to the
// database, which gives no verdict, so the guess is not counted. The cached login
// must be dropped then, or every later guess is checked against the cached password,
// uncounted, until the entry is older than positive_revalidation_window.
func TestUserAPIUnverifiableStoredHashDropsCachedLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	lookupCache := config.DefaultLookupCacheConfig()
	login := startUserAPIWithLookupCache(t, rdb, &lookupCache)

	if code := login(account.Email, account.Password); code != http.StatusOK {
		t.Fatalf("login with a valid stored hash: %d, want %d", code, http.StatusOK)
	}
	common.StoreUnverifiableHash(t, rdb, account.Email, account.Password)

	for i := 1; i <= 3; i++ {
		if code := login(account.Email, fmt.Sprintf("guess-%d", i)); code != http.StatusServiceUnavailable {
			t.Errorf("login with guess %d against an unverifiable stored hash: %d, want %d", i, code, http.StatusServiceUnavailable)
		}
	}
	if code := login(account.Email, account.Password); code != http.StatusServiceUnavailable {
		t.Errorf("login with the cached password after the guesses: %d, want %d (the uncounted guesses were checked against the cached login)", code, http.StatusServiceUnavailable)
	}
}
