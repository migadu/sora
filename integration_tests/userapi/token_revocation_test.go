//go:build integration

package userapi

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
)

// loginFor authenticates the given account against the User API and returns the JWT.
func (tc *TestContext) loginFor(t *testing.T, email, password string) string {
	t.Helper()
	resp := tc.makeRequest(t, "POST", "/user/auth/login", map[string]string{
		"email":    email,
		"password": password,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login for %s: expected 200, got %d", email, resp.StatusCode)
	}
	var body map[string]any
	parseJSON(t, resp, &body)
	tok, _ := body["token"].(string)
	if tok == "" {
		t.Fatalf("login for %s: empty token", email)
	}
	return tok
}

func (tc *TestContext) refresh(t *testing.T, token string) int {
	t.Helper()
	resp := tc.makeRequest(t, "POST", "/user/auth/refresh", map[string]string{"token": token})
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestTokenRevocation_OnRefresh verifies the M10 refresh-gate: a stateless JWT can
// still be renewed normally, but renewal is refused once the account is deleted or
// its password is changed — bounding a leaked/post-revocation token to one window.
func TestTokenRevocation_OnRefresh(t *testing.T) {
	tc := setupTestServer(t)
	ctx := context.Background()

	t.Run("Control_RefreshSucceeds", func(t *testing.T) {
		acct := common.CreateTestAccount(t, tc.RDB)
		token := tc.loginFor(t, acct.Email, acct.Password)
		if code := tc.refresh(t, token); code != http.StatusOK {
			t.Fatalf("expected refresh to succeed (200), got %d", code)
		}
	})

	t.Run("PasswordChange_InvalidatesRefresh", func(t *testing.T) {
		acct := common.CreateTestAccount(t, tc.RDB)
		token := tc.loginFor(t, acct.Email, acct.Password)

		// Sanity: refresh works before the change.
		if code := tc.refresh(t, token); code != http.StatusOK {
			t.Fatalf("pre-change refresh: expected 200, got %d", code)
		}

		// Ensure the new credentials.updated_at lands in a later whole second than
		// the token's auth_epoch (which is second-granular).
		time.Sleep(1100 * time.Millisecond)

		if err := tc.RDB.UpdateAccountWithRetry(ctx, db.UpdateAccountRequest{
			Email:    acct.Email,
			Password: "an-entirely-new-password-1!",
			HashType: "bcrypt",
		}); err != nil {
			t.Fatalf("change password: %v", err)
		}

		// The old token must no longer be refreshable.
		if code := tc.refresh(t, token); code != http.StatusUnauthorized {
			t.Fatalf("post-change refresh: expected 401, got %d", code)
		}
	})

	t.Run("AccountDelete_InvalidatesRefresh", func(t *testing.T) {
		acct := common.CreateTestAccount(t, tc.RDB)
		token := tc.loginFor(t, acct.Email, acct.Password)

		if code := tc.refresh(t, token); code != http.StatusOK {
			t.Fatalf("pre-delete refresh: expected 200, got %d", code)
		}

		if err := tc.RDB.DeleteAccountWithRetry(ctx, acct.Email); err != nil {
			t.Fatalf("delete account: %v", err)
		}

		if code := tc.refresh(t, token); code != http.StatusUnauthorized {
			t.Fatalf("post-delete refresh: expected 401, got %d", code)
		}
	})
}
