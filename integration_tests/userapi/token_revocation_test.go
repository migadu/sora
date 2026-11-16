//go:build integration

package userapi

import (
	"context"
	"fmt"
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

// TestTokenRefresh_RefusesReassignedCredential verifies that POST /user/auth/refresh
// binds token renewal to the token's original account_id, not merely its address and
// second-granular auth_epoch. If a credential is moved to another account (whose
// credentials.updated_at is unchanged) or an account is purged and its address is
// recreated on a new account within the same Unix second, refreshing the former
// owner's JWT must be refused 401 rather than minting a valid JWT for the new owner's
// account_id.
func TestTokenRefresh_RefusesReassignedCredential(t *testing.T) {
	tc := setupTestServer(t)
	ctx := context.Background()

	assertRefreshRefused := func(t *testing.T, token string, oldAccountID, newAccountID int64, secretMailbox string) {
		t.Helper()
		resp := tc.makeRequest(t, "POST", "/user/auth/refresh", map[string]string{"token": token})
		if resp.StatusCode == http.StatusOK {
			var body map[string]any
			parseJSON(t, resp, &body)
			gotID := int64(body["account_id"].(float64))
			mintedToken, _ := body["token"].(string)

			req, err := http.NewRequest("GET", tc.Server.URL+"/user/mailboxes", nil)
			if err != nil {
				t.Fatalf("new mailboxes request: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+mintedToken)
			mbResp, err := tc.HTTPClient.Do(req)
			if err != nil {
				t.Fatalf("GET /user/mailboxes with refreshed token: %v", err)
			}
			var mbBody map[string]any
			parseJSON(t, mbResp, &mbBody)

			t.Fatalf("refresh of account %d token after credential moved to account %d returned 200 and minted token for account_id=%d (mailboxes=%v, expected %q to stay inaccessible); want 401 Unauthorized",
				oldAccountID, newAccountID, gotID, mbBody["mailboxes"], secretMailbox)
		}

		if resp.StatusCode != http.StatusUnauthorized {
			defer resp.Body.Close()
			t.Fatalf("refresh status = %d, want 401 Unauthorized", resp.StatusCode)
		}
		if got := resp.Header.Values("WWW-Authenticate"); len(got) != 1 || got[0] != `Bearer realm="user-api", error="invalid_token"` {
			resp.Body.Close()
			t.Fatalf("WWW-Authenticate = %q, want Bearer invalid_token challenge", got)
		}
		var errBody map[string]string
		parseJSON(t, resp, &errBody)
		if errBody["error"] != "Invalid or expired token" {
			t.Fatalf("error body = %q, want %q", errBody["error"], "Invalid or expired token")
		}
	}

	t.Run("CredentialReassignedToAnotherAccount", func(t *testing.T) {
		acctA := common.CreateTestAccount(t, tc.RDB)
		acctB := common.CreateTestAccount(t, tc.RDB)
		idA, err := tc.RDB.GetAccountIDByAddressWithRetry(ctx, acctA.Email)
		if err != nil {
			t.Fatalf("account A id: %v", err)
		}
		idB, err := tc.RDB.GetAccountIDByAddressWithRetry(ctx, acctB.Email)
		if err != nil {
			t.Fatalf("account B id: %v", err)
		}
		if err := tc.RDB.CreateMailboxWithRetry(ctx, idB, "PrivateToB", nil); err != nil {
			t.Fatalf("create mailbox on B: %v", err)
		}

		sharedAddr := fmt.Sprintf("sales-reassign-%d@example.com", time.Now().UnixNano())
		const sharedPass = "shared-role-password-1!"
		if err := tc.RDB.AddCredentialWithRetry(ctx, db.AddCredentialRequest{
			AccountID:   idA,
			NewEmail:    sharedAddr,
			NewPassword: sharedPass,
			NewHashType: "bcrypt",
		}); err != nil {
			t.Fatalf("add credential to A: %v", err)
		}

		tokenA := tc.loginFor(t, sharedAddr, sharedPass)
		if code := tc.refresh(t, tokenA); code != http.StatusOK {
			t.Fatalf("pre-reassignment refresh: expected 200, got %d", code)
		}

		// Reassign the credential from Account A to Account B (as modeled by
		// trigger_credentials_changed in migration 000069). credentials has no
		// BEFORE UPDATE trigger bumping updated_at on account_id updates.
		if _, err := tc.RDB.ExecWithRetry(ctx,
			`UPDATE credentials SET account_id = $1 WHERE LOWER(address) = LOWER($2)`,
			idB, sharedAddr,
		); err != nil {
			t.Fatalf("reassign credential to B: %v", err)
		}

		assertRefreshRefused(t, tokenA, idA, idB, "PrivateToB")

		// Account B's own fresh login on the reassigned address succeeds and refreshes.
		tokenB := tc.loginFor(t, sharedAddr, sharedPass)
		if code := tc.refresh(t, tokenB); code != http.StatusOK {
			t.Fatalf("fresh Account B token refresh: expected 200, got %d", code)
		}
	})

	t.Run("SameSecondPurgeAndRecreationOnAnotherAccount", func(t *testing.T) {
		recycledAddr := fmt.Sprintf("sales-recycle-%d@example.com", time.Now().UnixNano())
		acctA := common.CreateTestAccountWithEmail(t, tc.RDB, recycledAddr, "password-for-a-only-1!")
		idA, err := tc.RDB.GetAccountIDByAddressWithRetry(ctx, acctA.Email)
		if err != nil {
			t.Fatalf("account A id: %v", err)
		}

		tokenA := tc.loginFor(t, recycledAddr, acctA.Password)
		_, epochA, err := tc.RDB.GetCredentialEpochWithRetry(ctx, recycledAddr)
		if err != nil {
			t.Fatalf("epoch A: %v", err)
		}

		// Soft-delete and purge Account A's credential, then recreate the same address
		// on a brand-new Account C with a completely different password.
		if err := tc.RDB.DeleteAccountWithRetry(ctx, recycledAddr); err != nil {
			t.Fatalf("delete account A: %v", err)
		}
		if _, err := tc.RDB.ExecWithRetry(ctx, `DELETE FROM credentials WHERE account_id = $1`, idA); err != nil {
			t.Fatalf("purge credentials of A: %v", err)
		}

		acctC := common.CreateTestAccountWithEmail(t, tc.RDB, recycledAddr, "brand-new-password-for-c-9!")
		idC, err := tc.RDB.GetAccountIDByAddressWithRetry(ctx, acctC.Email)
		if err != nil {
			t.Fatalf("account C id: %v", err)
		}
		if idC == idA {
			t.Fatalf("expected distinct account ID for C, got %d", idC)
		}
		if err := tc.RDB.CreateMailboxWithRetry(ctx, idC, "PrivateToC", nil); err != nil {
			t.Fatalf("create mailbox on C: %v", err)
		}

		// Pin C's credential timestamp into the same whole Unix second as tokenA's
		// auth_epoch so the test deterministically exercises same-second recreation
		// regardless of CI runner speed.
		sameSecond := time.Unix(epochA.Unix(), 500_000_000).UTC()
		if _, err := tc.RDB.ExecWithRetry(ctx,
			`UPDATE credentials SET created_at = $1, updated_at = $1 WHERE account_id = $2`,
			sameSecond, idC,
		); err != nil {
			t.Fatalf("pin C credential timestamp to same second: %v", err)
		}

		assertRefreshRefused(t, tokenA, idA, idC, "PrivateToC")

		// Account C's own fresh login succeeds and refreshes normally.
		tokenC := tc.loginFor(t, recycledAddr, acctC.Password)
		if code := tc.refresh(t, tokenC); code != http.StatusOK {
			t.Fatalf("fresh Account C token refresh: expected 200, got %d", code)
		}
	})
}
