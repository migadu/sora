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

// TestUserAPIDatabaseOutageDropsCachedLogin: a login in the lookup cache is accepted
// during a database outage while it is younger than positive_revalidation_window (30s
// by default). A password that misses it goes to the database, which gives no
// verdict, so the guess is not counted. The cached login must be dropped then, or
// every later guess is checked against the cached password, uncounted, until the entry
// is older than the window. Once the database is back, the user logs in: the guesses
// were not counted.
//
// The token of a login needs the database too (its password epoch), so during the
// outage every login is answered 503, cached or not. The log line says where the
// password was checked.
func TestUserAPIDatabaseOutageDropsCachedLogin(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	account := common.CreateTestAccount(t, rdb)
	lookupCache := config.DefaultLookupCacheConfig()
	login := startUserAPIWithLookupCache(t, rdb, &lookupCache)

	if code := login(account.Email, account.Password); code != http.StatusOK {
		t.Fatalf("login before the outage: %d, want %d", code, http.StatusOK)
	}

	outage.Begin()
	// Before any guess the cached login is accepted, and only its token fails.
	logs := common.CaptureLogs(t)
	if code := login(account.Email, account.Password); code != http.StatusServiceUnavailable {
		t.Errorf("login with the cached password during the outage, before any guess: %d, want %d", code, http.StatusServiceUnavailable)
	}
	logs.WaitForLine(t, "Error fetching credential epoch")

	for i := 1; i <= 3; i++ {
		if code := login(account.Email, fmt.Sprintf("guess-%d", i)); code != http.StatusServiceUnavailable {
			t.Errorf("login with guess %d during the outage: %d, want %d", i, code, http.StatusServiceUnavailable)
		}
	}
	logs = common.CaptureLogs(t)
	if code := login(account.Email, account.Password); code != http.StatusServiceUnavailable {
		t.Errorf("login with the cached password after the guesses: %d, want %d", code, http.StatusServiceUnavailable)
	}
	// The credentials were asked of the database, not accepted from the cache: the
	// uncounted guesses were not checked against the cached login.
	logs.WaitForLine(t, "Error retrieving credentials")
	outage.End()

	if code := login(account.Email, account.Password); code != http.StatusOK {
		t.Errorf("login after the outage: %d, want %d (the guesses were counted as failed logins)", code, http.StatusOK)
	}
}
