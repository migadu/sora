//go:build integration

package userapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/userapi"
)

// TestUserAPILogin_NULAndInvalidAddressesAreRefused401AndRateLimited proves that
// logins carrying NUL bytes (which PostgreSQL rejects with SQLSTATE 22021) or
// other non-address strings are answered 401 {"error": "Invalid credentials"}
// rather than 503 Service Unavailable, and are counted by the auth rate limiter
// so an attacker cannot probe indefinitely with NUL-containing emails.
func TestUserAPILogin_NULAndInvalidAddressesAreRefused401AndRateLimited(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	srv, err := userapi.New(rdb, userapi.ServerOptions{
		Name:          fmt.Sprintf("test-userapi-nul-login-%d", time.Now().UnixNano()),
		Addr:          "127.0.0.1:0",
		JWTSecret:     "test-secret-key-for-testing-only",
		TokenDuration: time.Hour,
		TokenIssuer:   "test-issuer",
		AuthRateLimit: server.AuthRateLimiterConfig{
			Enabled:                  true,
			MaxAttemptsPerIPUsername: 0, // Tier 2 IP-level test across distinct bad emails
			MaxAttemptsPerIP:         3,
			IPBlockDuration:          2 * time.Minute,
			IPWindowDuration:         5 * time.Minute,
			DelayStartThreshold:      100,
			CleanupInterval:          time.Minute,
		},
	})
	if err != nil {
		t.Fatalf("userapi.New: %v", err)
	}

	ts := httptest.NewServer(srv.SetupRoutes())
	t.Cleanup(ts.Close)
	client := ts.Client()

	postRawLogin := func(rawJSON string) (int, string) {
		t.Helper()
		resp, err := client.Post(ts.URL+"/user/auth/login", "application/json", strings.NewReader(rawJSON))
		if err != nil {
			t.Fatalf("POST /user/auth/login: %v", err)
		}
		defer resp.Body.Close()
		var body map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body["error"]
	}

	// Three malformed / NUL-containing login attempts from the same IP.
	// On unpatched main, the first two reach PostgreSQL, fail with SQLSTATE 22021,
	// answer 503 "Service unavailable", and skip RecordAuthAttempt.
	for i, raw := range []string{
		`{"email":"a\u0000b@example.com","password":"wrong-password-1"}`,
		`{"email":"user@example.com@\u0000","password":"wrong-password-2"}`,
		`{"email":"not-an-email","password":"wrong-password-3"}`,
	} {
		code, errMsg := postRawLogin(raw)
		if code != http.StatusUnauthorized || errMsg != "Invalid credentials" {
			t.Fatalf("attempt %d (%s): got %d (%q), want 401 (\"Invalid credentials\")", i+1, raw, code, errMsg)
		}
	}

	// Because all three failed attempts were recorded, Tier 2 has now blocked
	// this IP: even a valid login from the same IP must be refused 401.
	validBody, _ := json.Marshal(map[string]string{
		"email":    account.Email,
		"password": account.Password,
	})
	code, errMsg := postRawLogin(string(validBody))
	if code != http.StatusUnauthorized || errMsg != "Invalid credentials" {
		t.Fatalf("valid login after 3 invalid/NUL failures from same IP: got %d (%q), want 401 (rate limit bypassed)", code, errMsg)
	}
}

// TestUserAPILogin_IDNAndCanonicalEmailNormalization proves that User API login
// folds Unicode IDN domains (U-labels) and whitespace/case variants via
// server.NewAddress to the canonical A-label address stored by CreateAccount:
//   - logging in with "  ANNA-...@MÜNCHEN.DE  " succeeds against the stored
//     "anna-...@xn--mnchen-3ya.de" credential;
//   - LoginResponse.Email, JWT claims (email, sub), and /user/auth/refresh all
//     carry the canonical A-label address;
//   - s.authCache keys on the canonical address so U-label and A-label logins
//     share one cache entry;
//   - Tier-1 rate limiting shares one bucket across U-label and A-label forms.
func TestUserAPILogin_IDNAndCanonicalEmailNormalization(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	ctx := context.Background()
	const jwtSecret = "test-secret-key-for-testing-only"

	t.Run("U-label login canonical JWT refresh and shared authCache", func(t *testing.T) {
		rdb := common.SetupTestDatabase(t)
		stamp := time.Now().UnixNano()
		unicodeEmail := fmt.Sprintf("anna-%d@münchen.de", stamp)
		asciiEmail := fmt.Sprintf("anna-%d@xn--mnchen-3ya.de", stamp)
		const password = "correct-idn-password-123!"

		accountID, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
			Email:     unicodeEmail,
			Password:  password,
			IsPrimary: true,
			HashType:  "bcrypt",
		})
		if err != nil {
			t.Fatalf("CreateAccountWithRetry(%q): %v", unicodeEmail, err)
		}

		lookupCache := config.DefaultLookupCacheConfig()
		srv, err := userapi.New(rdb, userapi.ServerOptions{
			Name:          fmt.Sprintf("test-userapi-idn-cache-%d", stamp),
			Addr:          "127.0.0.1:0",
			JWTSecret:     jwtSecret,
			TokenDuration: time.Hour,
			TokenIssuer:   "test-issuer",
			LookupCache:   &lookupCache,
		})
		if err != nil {
			t.Fatalf("userapi.New: %v", err)
		}

		ts := httptest.NewServer(srv.SetupRoutes())
		t.Cleanup(ts.Close)
		client := ts.Client()

		postJSON := func(path string, payload any) (*http.Response, []byte) {
			t.Helper()
			b, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			resp, err := client.Post(ts.URL+path, "application/json", bytes.NewReader(b))
			if err != nil {
				t.Fatalf("POST %s: %v", path, err)
			}
			defer resp.Body.Close()
			var raw bytes.Buffer
			_, _ = raw.ReadFrom(resp.Body)
			return resp, raw.Bytes()
		}

		// 1. Login with padded uppercase U-label address.
		submitted := "  " + strings.ToUpper(unicodeEmail) + "  "
		resp, raw := postJSON("/user/auth/login", map[string]string{
			"email":    submitted,
			"password": password,
		})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login with %q: status %d (%s), want 200", submitted, resp.StatusCode, string(raw))
		}

		var loginResp userapi.LoginResponse
		if err := json.Unmarshal(raw, &loginResp); err != nil {
			t.Fatalf("decode LoginResponse: %v", err)
		}
		if loginResp.Email != asciiEmail {
			t.Errorf("LoginResponse.Email = %q, want canonical %q", loginResp.Email, asciiEmail)
		}
		if loginResp.AccountID != accountID {
			t.Errorf("LoginResponse.AccountID = %d, want %d", loginResp.AccountID, accountID)
		}

		// 2. Verify JWT claims carry canonical A-label email & subject.
		var claims userapi.JWTClaims
		parsedTok, err := jwt.ParseWithClaims(loginResp.Token, &claims, func(tok *jwt.Token) (any, error) {
			return []byte(jwtSecret), nil
		})
		if err != nil || !parsedTok.Valid {
			t.Fatalf("parse issued JWT: err=%v valid=%v", err, parsedTok != nil && parsedTok.Valid)
		}
		if claims.Email != asciiEmail {
			t.Errorf("JWT claims.Email = %q, want %q", claims.Email, asciiEmail)
		}
		if claims.Subject != asciiEmail {
			t.Errorf("JWT claims.Subject = %q, want %q", claims.Subject, asciiEmail)
		}

		// 3. Refresh token succeeds and preserves canonical email.
		refResp, refRaw := postJSON("/user/auth/refresh", map[string]string{"token": loginResp.Token})
		if refResp.StatusCode != http.StatusOK {
			t.Fatalf("refresh token: status %d (%s), want 200", refResp.StatusCode, string(refRaw))
		}
		var refLoginResp userapi.LoginResponse
		if err := json.Unmarshal(refRaw, &refLoginResp); err != nil {
			t.Fatalf("decode refresh LoginResponse: %v", err)
		}
		if refLoginResp.Email != asciiEmail {
			t.Errorf("refresh LoginResponse.Email = %q, want %q", refLoginResp.Email, asciiEmail)
		}

		// 4. Prove authCache stored the canonical key: replace stored password hash in DB
		// (without touching updated_at) so only authCache knows `password`, then log in
		// with the A-label form. A 200 proves both forms share one cache entry.
		otherHash, err := db.GenerateBcryptHash("different-db-password-456!")
		if err != nil {
			t.Fatalf("GenerateBcryptHash: %v", err)
		}
		if err := rdb.UpdatePasswordWithRetry(ctx, asciiEmail, otherHash); err != nil {
			t.Fatalf("UpdatePasswordWithRetry: %v", err)
		}

		cachedResp, cachedRaw := postJSON("/user/auth/login", map[string]string{
			"email":    asciiEmail,
			"password": password,
		})
		if cachedResp.StatusCode != http.StatusOK {
			t.Fatalf("A-label login against cached U-label entry: status %d (%s), want 200", cachedResp.StatusCode, string(cachedRaw))
		}
	})

	t.Run("Tier-1 rate limit shares one bucket across U-label and A-label IDN forms", func(t *testing.T) {
		rdb := common.SetupTestDatabase(t)
		stamp := time.Now().UnixNano()
		unicodeEmail := fmt.Sprintf("karl-%d@münchen.de", stamp)
		asciiEmail := fmt.Sprintf("karl-%d@xn--mnchen-3ya.de", stamp)
		const password = "correct-idn-password-789!"

		if _, err := rdb.CreateAccountWithRetry(ctx, db.CreateAccountRequest{
			Email:     unicodeEmail,
			Password:  password,
			IsPrimary: true,
			HashType:  "bcrypt",
		}); err != nil {
			t.Fatalf("CreateAccountWithRetry(%q): %v", unicodeEmail, err)
		}

		srv, err := userapi.New(rdb, userapi.ServerOptions{
			Name:          fmt.Sprintf("test-userapi-idn-ratelimit-%d", stamp),
			Addr:          "127.0.0.1:0",
			JWTSecret:     jwtSecret,
			TokenDuration: time.Hour,
			TokenIssuer:   "test-issuer",
			AuthRateLimit: server.AuthRateLimiterConfig{
				Enabled:                  true,
				MaxAttemptsPerIPUsername: 3,
				IPUsernameBlockDuration:  2 * time.Minute,
				IPUsernameWindowDuration: 5 * time.Minute,
				MaxAttemptsPerIP:         0,
				DelayStartThreshold:      100,
				CleanupInterval:          time.Minute,
			},
		})
		if err != nil {
			t.Fatalf("userapi.New: %v", err)
		}

		ts := httptest.NewServer(srv.SetupRoutes())
		t.Cleanup(ts.Close)
		client := ts.Client()

		loginCode := func(email, pw string) int {
			t.Helper()
			b, _ := json.Marshal(map[string]string{"email": email, "password": pw})
			resp, err := client.Post(ts.URL+"/user/auth/login", "application/json", bytes.NewReader(b))
			if err != nil {
				t.Fatalf("POST /user/auth/login: %v", err)
			}
			defer resp.Body.Close()
			return resp.StatusCode
		}

		for i, form := range []string{unicodeEmail, strings.ToUpper(unicodeEmail), asciiEmail} {
			if code := loginCode(form, fmt.Sprintf("wrong-%d", i)); code != http.StatusUnauthorized {
				t.Fatalf("attempt %d (%q): got %d, want 401", i+1, form, code)
			}
		}

		if code := loginCode(asciiEmail, password); code != http.StatusUnauthorized {
			t.Fatalf("correct password under A-label after 3 mixed U-label/A-label failures: got %d, want 401", code)
		}
		if code := loginCode(unicodeEmail, password); code != http.StatusUnauthorized {
			t.Fatalf("correct password under U-label after 3 mixed U-label/A-label failures: got %d, want 401", code)
		}
	})

	t.Run("padded and cased ASCII login normalizes JWT response and authCache key", func(t *testing.T) {
		rdb := common.SetupTestDatabase(t)
		account := common.CreateTestAccount(t, rdb)

		lookupCache := config.DefaultLookupCacheConfig()
		srv, err := userapi.New(rdb, userapi.ServerOptions{
			Name:          fmt.Sprintf("test-userapi-ascii-norm-%d", time.Now().UnixNano()),
			Addr:          "127.0.0.1:0",
			JWTSecret:     jwtSecret,
			TokenDuration: time.Hour,
			TokenIssuer:   "test-issuer",
			LookupCache:   &lookupCache,
		})
		if err != nil {
			t.Fatalf("userapi.New: %v", err)
		}

		ts := httptest.NewServer(srv.SetupRoutes())
		t.Cleanup(ts.Close)
		client := ts.Client()

		submitted := "  " + strings.ToUpper(account.Email) + "  "
		b, _ := json.Marshal(map[string]string{"email": submitted, "password": account.Password})
		resp, err := client.Post(ts.URL+"/user/auth/login", "application/json", bytes.NewReader(b))
		if err != nil {
			t.Fatalf("POST /user/auth/login: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login with %q: status %d, want 200", submitted, resp.StatusCode)
		}

		var loginResp userapi.LoginResponse
		if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
			t.Fatalf("decode LoginResponse: %v", err)
		}
		if loginResp.Email != account.Email {
			t.Errorf("LoginResponse.Email = %q, want canonical %q", loginResp.Email, account.Email)
		}

		otherHash, err := db.GenerateBcryptHash("different-ascii-db-password!")
		if err != nil {
			t.Fatalf("GenerateBcryptHash: %v", err)
		}
		if err := rdb.UpdatePasswordWithRetry(ctx, account.Email, otherHash); err != nil {
			t.Fatalf("UpdatePasswordWithRetry: %v", err)
		}

		// Canonical lowercase login must hit the positive cache entry created above.
		b2, _ := json.Marshal(map[string]string{"email": account.Email, "password": account.Password})
		resp2, err := client.Post(ts.URL+"/user/auth/login", "application/json", bytes.NewReader(b2))
		if err != nil {
			t.Fatalf("POST /user/auth/login (canonical): %v", err)
		}
		defer resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			t.Fatalf("canonical login missed cache entry from padded/uppercase login: status %d, want 200", resp2.StatusCode)
		}
	})
}
