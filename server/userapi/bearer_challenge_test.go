package userapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/server"
)

const (
	// The challenges a 401 of the User API carries. RFC 9110 section 15.5.2: "The server
	// generating a 401 response MUST send a WWW-Authenticate header field (Section 11.6.1)
	// containing at least one challenge applicable to the target resource." RFC 6750
	// section 3.1: a request that "lacks any authentication information (e.g., the client
	// was unaware that authentication is necessary or attempted using an unsupported
	// authentication method)" gets no error code; a token that is "expired, revoked,
	// malformed, or invalid for other reasons" gets error="invalid_token".
	noTokenChallenge      = `Bearer realm="user-api"`
	refusedTokenChallenge = `Bearer realm="user-api", error="invalid_token"`
)

// Every 401 of the User API carries the realm's Bearer challenge, the login and refresh
// endpoints included (#790): RFC 9110 section 15.5.2 requires one on every 401, and RFC
// 6750 section 3 lets a resource server include it "in response to other conditions as
// well". A refresh presents a token, so its refusal says error="invalid_token"; a login
// presents none and gets the challenge without an error code.
func TestUnauthorizedCarriesBearerChallenge(t *testing.T) {
	s, err := New(nil, ServerOptions{Name: "challenge", JWTSecret: "bearer-challenge-test-secret-32-bytes!"})
	if err != nil {
		t.Fatal(err)
	}
	s.tokenDuration = -time.Hour // the token expired an hour ago
	expired, _, err := s.generateToken("user@example.com", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	handler := s.SetupRoutes()

	for _, tc := range []struct {
		name, method, path, auth, body string
		want                           string
	}{
		{name: "no authorization header", method: http.MethodGet, path: "/user/mailboxes", want: noTokenChallenge},
		{name: "not a bearer token", method: http.MethodGet, path: "/user/mailboxes", auth: "Basic dXNlcjpwYXNz", want: noTokenChallenge},
		{name: "bearer without a token", method: http.MethodGet, path: "/user/filters", auth: "Bearer", want: noTokenChallenge},
		{name: "expired token", method: http.MethodGet, path: "/user/mailboxes", auth: "Bearer " + expired, want: refusedTokenChallenge},
		{name: "malformed token", method: http.MethodGet, path: "/user/messages/1", auth: "Bearer not.a.jwt", want: refusedTokenChallenge},
		{name: "refresh of a malformed token", method: http.MethodPost, path: "/user/auth/refresh", body: `{"token":"not.a.jwt"}`, want: refusedTokenChallenge},
		{name: "refresh of an expired token", method: http.MethodPost, path: "/user/auth/refresh", body: `{"token":"` + expired + `"}`, want: refusedTokenChallenge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if tc.auth != "" {
				r.Header.Set("Authorization", tc.auth)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status %d, want 401 (body %q)", w.Code, w.Body.String())
			}
			if got := w.Header().Values("WWW-Authenticate"); len(got) != 1 || got[0] != tc.want {
				t.Errorf("WWW-Authenticate = %q, want %q", got, tc.want)
			}
		})
	}

	// A refused login presents no bearer token. It comes from a blocked address, which is
	// answered as a wrong password is (security-audit M14) before any database lookup.
	t.Run("refused login", func(t *testing.T) {
		const clientIP = "203.0.113.9"
		limiter := server.NewAuthRateLimiter("user-api", "test", "", server.AuthRateLimiterConfig{
			Enabled:          true,
			MaxAttemptsPerIP: 1,
			IPBlockDuration:  time.Hour,
			IPWindowDuration: time.Hour,
			CleanupInterval:  time.Hour,
		})
		defer limiter.Stop()
		clientAddr := &server.StringAddr{Addr: clientIP}
		limiter.RecordAuthAttempt(context.Background(), clientAddr, "guess@example.com", false)
		if !limiter.IsIPBlocked(clientAddr) {
			t.Fatal("setup: address is not blocked")
		}
		login := &Server{name: "challenge", authLimiter: limiter}
		r := httptest.NewRequest(http.MethodPost, "/user/auth/login",
			strings.NewReader(`{"email":"user@example.com","password":"wrong"}`))
		r.RemoteAddr = clientIP + ":40000"
		w := httptest.NewRecorder()
		login.handleLogin(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401 (body %q)", w.Code, w.Body.String())
		}
		if got := w.Header().Values("WWW-Authenticate"); len(got) != 1 || got[0] != noTokenChallenge {
			t.Errorf("WWW-Authenticate = %q, want %q", got, noTokenChallenge)
		}
	})
}
