//go:build integration

package userapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/userapi"
)

// loginStatus attempts a login and returns the status code.
func (tc *TestContext) loginStatus(t *testing.T, email, password string) int {
	t.Helper()
	resp := tc.makeRequest(t, "POST", "/user/auth/login", map[string]string{"email": email, "password": password})
	defer resp.Body.Close()
	return resp.StatusCode
}

// TestLoginRefusesChangedCredentialsAtOnce verifies that a password change, a removed
// credential and a deleted account stop User API logins the moment the change is
// committed, with a lookup cache configured, whichever node or tool made the change: a
// login served from a stale cache would be issued a token stamped with the epoch read
// after the change, which every later refresh accepts.
func TestLoginRefusesChangedCredentialsAtOnce(t *testing.T) {
	tc := setupTestServerWith(t, func(o *userapi.ServerOptions) {
		o.LookupCache = &config.LookupCacheConfig{
			Enabled:         true,
			PositiveTTL:     "5m",
			NegativeTTL:     "1m",
			MaxSize:         1000,
			CleanupInterval: "5m",
		}
	})
	ctx := context.Background()

	// Each case signs in twice before the change: once to be looked up, once to be
	// answered from whatever the server kept of the first.
	t.Run("PasswordChange", func(t *testing.T) {
		acct := common.CreateTestAccount(t, tc.RDB)
		tc.loginFor(t, acct.Email, acct.Password)
		tc.loginFor(t, acct.Email, acct.Password)

		if err := tc.RDB.UpdateAccountWithRetry(ctx, db.UpdateAccountRequest{
			Email: acct.Email, Password: "an-entirely-new-password-1!", HashType: "bcrypt",
		}); err != nil {
			t.Fatalf("change password: %v", err)
		}

		if code := tc.loginStatus(t, acct.Email, acct.Password); code != http.StatusUnauthorized {
			t.Errorf("old password after the change: got %d, want 401", code)
		}
		tc.loginFor(t, acct.Email, "an-entirely-new-password-1!")
	})

	t.Run("CredentialRemoved", func(t *testing.T) {
		acct := common.CreateTestAccount(t, tc.RDB)
		accountID, err := tc.RDB.GetAccountIDByAddressWithRetry(ctx, acct.Email)
		if err != nil {
			t.Fatalf("account id: %v", err)
		}
		alias := fmt.Sprintf("alias-%d@example.com", time.Now().UnixNano())
		if err := tc.RDB.AddCredentialWithRetry(ctx, db.AddCredentialRequest{
			AccountID: accountID, NewEmail: alias, NewPassword: "alias-password-1!", NewHashType: "bcrypt",
		}); err != nil {
			t.Fatalf("add credential: %v", err)
		}
		tc.loginFor(t, alias, "alias-password-1!")
		tc.loginFor(t, alias, "alias-password-1!")

		if err := tc.RDB.DeleteCredentialWithRetry(ctx, alias); err != nil {
			t.Fatalf("delete credential: %v", err)
		}

		if code := tc.loginStatus(t, alias, "alias-password-1!"); code != http.StatusUnauthorized {
			t.Errorf("removed credential: got %d, want 401", code)
		}
	})

	t.Run("AccountDeleted", func(t *testing.T) {
		acct := common.CreateTestAccount(t, tc.RDB)
		tc.loginFor(t, acct.Email, acct.Password)
		tc.loginFor(t, acct.Email, acct.Password)

		if err := tc.RDB.DeleteAccountWithRetry(ctx, acct.Email); err != nil {
			t.Fatalf("delete account: %v", err)
		}

		if code := tc.loginStatus(t, acct.Email, acct.Password); code != http.StatusUnauthorized {
			t.Errorf("deleted account: got %d, want 401", code)
		}
	})
}
