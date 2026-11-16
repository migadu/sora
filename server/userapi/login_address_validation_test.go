package userapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/testutils"
)

// A login whose email does not parse as a user address (missing @, NUL byte,
// invalid domain or IDN label, internal whitespace, or an @-suffix) names no
// account. Like an unknown user on a backend or an invalid address on the User
// API proxy (#850), it must be gated by the rate limiter first, answered 401
// {"error": "Invalid credentials"} with a wrong password's Bearer challenge after one
// dummy password verification, and recorded as a failed login attempt without touching
// the auth cache or the database.
func TestLoginWithInvalidAddressLooksLikeAWrongPasswordWithoutDatabase(t *testing.T) {
	origCost := db.BcryptCost
	db.BcryptCost = bcrypt.MinCost
	t.Cleanup(func() { db.BcryptCost = origCost })

	cases := []struct {
		name  string
		body1 string
		body2 string
	}{
		{
			name:  "missing at",
			body1: `{"email":"not-an-email","password":"wrong-password"}`,
			body2: `{"email":"  NOT-AN-EMAIL  ","password":"wrong-password"}`,
		},
		{
			name:  "empty domain",
			body1: `{"email":"john@","password":"wrong-password"}`,
			body2: `{"email":"JOHN@","password":"wrong-password"}`,
		},
		{
			name:  "empty local part",
			body1: `{"email":"@example.com","password":"wrong-password"}`,
			body2: `{"email":"@EXAMPLE.COM","password":"wrong-password"}`,
		},
		{
			name:  "nul byte in local part",
			body1: `{"email":"a\u0000b@example.com","password":"wrong-password"}`,
			body2: `{"email":"A\u0000B@EXAMPLE.COM","password":"wrong-password"}`,
		},
		{
			name:  "nul byte in domain",
			body1: `{"email":"user@ex\u0000ample.com","password":"wrong-password"}`,
			body2: `{"email":"USER@EX\u0000AMPLE.COM","password":"wrong-password"}`,
		},
		{
			name:  "bare nul byte",
			body1: `{"email":"\u0000","password":"wrong-password"}`,
			body2: `{"email":" \u0000 ","password":"wrong-password"}`,
		},
		{
			name:  "nul byte in suffix",
			body1: `{"email":"user@example.com@\u0000","password":"wrong-password"}`,
			body2: `{"email":"USER@EXAMPLE.COM@\u0000","password":"wrong-password"}`,
		},
		{
			name:  "master or token suffix",
			body1: `{"email":"user@example.com@admin","password":"wrong-password"}`,
			body2: `{"email":"USER@EXAMPLE.COM@admin","password":"wrong-password"}`,
		},
		{
			name:  "internal whitespace",
			body1: `{"email":"user @example.com","password":"wrong-password"}`,
			body2: `{"email":"USER @EXAMPLE.COM","password":"wrong-password"}`,
		},
		{
			name:  "invalid ascii domain",
			body1: `{"email":"user@bad_domain","password":"wrong-password"}`,
			body2: `{"email":"USER@BAD_DOMAIN","password":"wrong-password"}`,
		},
		{
			name:  "invalid IDN domain",
			body1: `{"email":"user@bü_cher.example","password":"wrong-password"}`,
			body2: `{"email":"USER@BÜ_CHER.EXAMPLE","password":"wrong-password"}`,
		},
		{
			name:  "invalid UTF-8 byte in domain",
			body1: "{\"email\":\"user@ex\xffample.com\",\"password\":\"wrong-password\"}",
			body2: "{\"email\":\"USER@EX\xffAMPLE.COM\",\"password\":\"wrong-password\"}",
		},
	}

	for idx, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			limiter := server.NewAuthRateLimiter("user-api", "test-invalid-addr", "", server.AuthRateLimiterConfig{
				Enabled:                  true,
				MaxAttemptsPerIPUsername: 2,
				IPUsernameBlockDuration:  time.Hour,
				IPUsernameWindowDuration: time.Hour,
				DelayStartThreshold:      100,
				CleanupInterval:          time.Hour,
			})
			t.Cleanup(limiter.Stop)

			cache := lookupcache.New("userapi", "test-invalid-addr", 5*time.Minute, time.Minute, 100, 5*time.Minute, 30*time.Second)
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = cache.Stop(ctx)
			})

			// s.rdb is nil: touching PostgreSQL panics and fails the test.
			s := &Server{name: "test-invalid-addr", authCache: cache, authLimiter: limiter}
			clientAddr := fmt.Sprintf("198.51.100.%d:40000", idx+1)

			postLogin := func(rawBody string) (*httptest.ResponseRecorder, int) {
				t.Helper()
				req := httptest.NewRequest(http.MethodPost, "/user/auth/login", strings.NewReader(rawBody))
				req.Header.Set("Content-Type", "application/json")
				req.RemoteAddr = clientAddr
				rec := httptest.NewRecorder()

				before := testutils.PasswordVerifications()
				var panicked any
				func() {
					defer func() { panicked = recover() }()
					s.handleLogin(rec, req)
				}()
				if panicked != nil {
					t.Fatalf("handleLogin panicked (reached nil database instead of refusing invalid address): %v", panicked)
				}
				return rec, testutils.PasswordVerifications() - before
			}

			assertRefused401 := func(step string, rec *httptest.ResponseRecorder, gotVerifications, wantVerifications int) {
				t.Helper()
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("%s: status %d (%q), want 401", step, rec.Code, rec.Body.String())
				}
				if got := rec.Header().Values("WWW-Authenticate"); len(got) != 1 || got[0] != noTokenChallenge {
					t.Errorf("%s: WWW-Authenticate = %q, want %q", step, got, noTokenChallenge)
				}
				var body map[string]string
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != "Invalid credentials" {
					t.Errorf("%s: body %q, want {\"error\": \"Invalid credentials\"}", step, rec.Body.String())
				}
				if gotVerifications != wantVerifications {
					t.Errorf("%s: %d password verifications, want %d", step, gotVerifications, wantVerifications)
				}
			}

			// First two attempts run DummyVerifyPassword and count toward Tier 1.
			rec1, ver1 := postLogin(tc.body1)
			assertRefused401("attempt 1", rec1, ver1, 1)

			rec2, ver2 := postLogin(tc.body2)
			assertRefused401("attempt 2", rec2, ver2, 1)

			// Third attempt from the same IP+key is blocked by CanAttemptAuth before bcrypt.
			rec3, ver3 := postLogin(tc.body1)
			assertRefused401("attempt 3 (rate-limited)", rec3, ver3, 0)

			hits, misses, size, _ := cache.GetStats()
			if hits != 0 || misses != 0 || size != 0 {
				t.Errorf("authCache touched for invalid address: hits=%d misses=%d size=%d, want 0/0/0", hits, misses, size)
			}
		})
	}
}

// A refresh token whose email claim is blank, malformed, NUL-containing, or
// carries an @-suffix names no valid credential and must be answered 401
// {"error": "Invalid or expired token"} with error="invalid_token" in the challenge
// before touching the database.
func TestRefreshTokenWithInvalidAddressClaimWithoutDatabase(t *testing.T) {
	s, err := New(nil, ServerOptions{
		Name:      "refresh-invalid-addr",
		JWTSecret: "refresh-address-test-secret-32-bytes!",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, badEmail := range []string{
		"",
		"   ",
		"not-an-email",
		"a\x00b@example.com",
		"user@example.com@\x00",
		"user@example.com@admin",
	} {
		t.Run(fmt.Sprintf("%q", badEmail), func(t *testing.T) {
			tok, _, err := s.generateToken(badEmail, 42, 100)
			if err != nil {
				t.Fatalf("generateToken: %v", err)
			}
			body, err := json.Marshal(RefreshTokenRequest{Token: tok})
			if err != nil {
				t.Fatalf("marshal refresh body: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/user/auth/refresh", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			var panicked any
			func() {
				defer func() { panicked = recover() }()
				s.handleRefreshToken(rec, req)
			}()
			if panicked != nil {
				t.Fatalf("handleRefreshToken panicked (reached nil database for %q): %v", badEmail, panicked)
			}
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status %d (%q), want 401", rec.Code, rec.Body.String())
			}
			if got := rec.Header().Values("WWW-Authenticate"); len(got) != 1 || got[0] != refusedTokenChallenge {
				t.Errorf("WWW-Authenticate = %q, want %q", got, refusedTokenChallenge)
			}
			var resp map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp["error"] != "Invalid or expired token" {
				t.Errorf("body %q, want {\"error\": \"Invalid or expired token\"}", rec.Body.String())
			}
		})
	}
}
