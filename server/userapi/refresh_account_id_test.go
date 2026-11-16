package userapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRefreshToken_RefusesNonPositiveAccountIDWithoutDatabase verifies that a
// refresh token carrying a missing or non-positive account_id claim names no
// valid account and is refused 401 with error="invalid_token" before touching
// PostgreSQL, matching userapiproxy's peekAuthIdentity guard.
func TestRefreshToken_RefusesNonPositiveAccountIDWithoutDatabase(t *testing.T) {
	s, err := New(nil, ServerOptions{
		Name:      "refresh-account-id",
		JWTSecret: "refresh-account-id-test-secret-32b!",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, badAccountID := range []int64{0, -1, -42} {
		t.Run(fmt.Sprintf("account_id=%d", badAccountID), func(t *testing.T) {
			tok, _, err := s.generateToken("user@example.com", badAccountID, 1_700_000_000)
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
				t.Fatalf("handleRefreshToken panicked (reached nil database for account_id=%d): %v", badAccountID, panicked)
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
