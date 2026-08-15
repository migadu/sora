//go:build integration

package userapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/userapi"
)

// TestUserAPI_RateLimiting_Tier1_KeyIsCanonical proves the Tier-1 (IP+username) key
// is canonicalised. The credential lookup is case-insensitive (it lowercases the
// address), but the rate limiter was keyed on the raw submitted string, so flipping
// the case of one character gave every attempt its own bucket and Tier 1 never
// engaged.
func TestUserAPI_RateLimiting_Tier1_KeyIsCanonical(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Tier 1 only; Tier 2 and progressive delays disabled so the assertion is on
	// blocking alone and never on timing.
	srv, err := userapi.New(rdb, userapi.ServerOptions{
		Name:          fmt.Sprintf("test-userapi-ratelimit-key-%d", time.Now().UnixNano()),
		Addr:          "127.0.0.1:0",
		JWTSecret:     "test-secret-key-for-testing-only",
		TokenDuration: 1 * time.Hour,
		TokenIssuer:   "test-issuer",
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled:                  true,
			MaxAttemptsPerIPUsername: 3,
			IPUsernameBlockDuration:  2 * time.Minute,
			IPUsernameWindowDuration: 5 * time.Minute,
			MaxAttemptsPerIP:         0,   // Tier 2 disabled
			DelayStartThreshold:      100, // delays disabled
			CleanupInterval:          1 * time.Minute,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	testServer := httptest.NewServer(srv.SetupRoutes())
	defer testServer.Close()
	client := testServer.Client()

	// upperAt returns the address with its i-th character upper-cased: a distinct
	// raw string that resolves to the very same account.
	upperAt := func(i int) string {
		return account.Email[:i] + strings.ToUpper(account.Email[i:i+1]) + account.Email[i+1:]
	}

	login := func(email, password string) int {
		body, _ := json.Marshal(map[string]string{"email": email, "password": password})
		resp, err := client.Post(testServer.URL+"/user/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login request failed: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// Three failures, each under a DIFFERENT raw string for the same account.
	for i := 0; i < 3; i++ {
		variant := upperAt(i)
		if code := login(variant, fmt.Sprintf("wrong-password-%d", i)); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d (%q): expected 401, got %d", i+1, variant, code)
		}
	}

	// A fourth, again-unseen case form of the same account — with the CORRECT
	// password. It must be refused (401, masked as bad credentials): the failures
	// above belong to the same canonical key.
	if code := login(upperAt(3), account.Password); code != http.StatusUnauthorized {
		t.Fatalf("login allowed after 3 failures for the same account (got %d): Tier 1 is bypassable by varying the case", code)
	}
	t.Log("✓ Tier 1 blocked the canonical key regardless of the submitted case")
}
