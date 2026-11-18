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
	"github.com/migadu/sora/server/userapi"
)

// TestUserAPILoginDuringDatabaseOutage: a login the database cannot answer is
// 503 Service Unavailable (RFC 9110 section 15.6.4), a temporary condition, not 500
// or 401, and it is not counted by the auth rate limiter, so the user logs in once
// the database is back.
func TestUserAPILoginDuringDatabaseOutage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	account := common.CreateTestAccount(t, rdb)

	srv, err := userapi.New(rdb, userapi.ServerOptions{
		Name:          fmt.Sprintf("test-userapi-db-outage-%d", time.Now().UnixNano()),
		Addr:          "127.0.0.1:0",
		JWTSecret:     "test-secret-key-for-testing-only",
		TokenDuration: time.Hour,
		TokenIssuer:   "test-issuer",
		AuthRateLimit: common.DBOutageAuthRateLimit(),
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	testServer := httptest.NewServer(srv.SetupRoutes())
	defer testServer.Close()

	login := func() int {
		body, _ := json.Marshal(map[string]string{"email": account.Email, "password": account.Password})
		resp, err := testServer.Client().Post(testServer.URL+"/user/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login request failed: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	outage.Begin()
	for i := 1; i <= 3; i++ {
		if code := login(); code != http.StatusServiceUnavailable {
			t.Errorf("login %d during a database outage: %d, want %d", i, code, http.StatusServiceUnavailable)
		}
	}
	outage.End()

	if code := login(); code != http.StatusOK {
		t.Errorf("login after the outage: %d, want %d", code, http.StatusOK)
	}
}

// TestUserAPIDatabaseOutageIgnoresLookupCache: the User API does not cache logins (a
// configured lookup_cache is ignored with a warning). Each login reads the hash and the
// token epoch together from the database, since a cached password verdict cannot supply
// the epoch of that same hash. So during a database outage a login is 503 whether its
// password logged in a moment ago or is a guess. The database gave no verdict, so none
// of them is counted, and the user logs in once the database is back. A login cache that
// came back and checked the guesses against the cached password, uncounted, fails here.
func TestUserAPIDatabaseOutageIgnoresLookupCache(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	account := common.CreateTestAccount(t, rdb)
	lookupCache := config.DefaultLookupCacheConfig()
	login := startUserAPIWithLookupCache(t, rdb, &lookupCache)

	if code := login(account.Email, account.Password); code != http.StatusOK {
		t.Fatalf("login before the outage: %d, want %d", code, http.StatusOK)
	}

	outage.Begin()
	// The password that just logged in is asked of the database too: no cache answers it.
	logs := common.CaptureLogs(t)
	if code := login(account.Email, account.Password); code != http.StatusServiceUnavailable {
		t.Errorf("login with the password that just logged in, during the outage: %d, want %d", code, http.StatusServiceUnavailable)
	}
	logs.WaitForLine(t, "Error retrieving credentials")

	// More guesses than the rate limit allows (common.DBOutageAuthRateLimit blocks
	// after two failures), so the login after the outage fails if any was counted.
	for i := 1; i <= 3; i++ {
		if code := login(account.Email, fmt.Sprintf("guess-%d", i)); code != http.StatusServiceUnavailable {
			t.Errorf("login with guess %d during the outage: %d, want %d", i, code, http.StatusServiceUnavailable)
		}
	}
	outage.End()

	if code := login(account.Email, account.Password); code != http.StatusOK {
		t.Errorf("login after the outage: %d, want %d (the outage logins were counted as failed logins)", code, http.StatusOK)
	}
}
