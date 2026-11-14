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
