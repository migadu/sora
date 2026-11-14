//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server/adminapi"
)

// TestAddressWithSlashNamesItsOwnAccount checks that an address whose local part
// holds a "/" (atext, RFC 5322 §3.2.3), sent as %2F (RFC 3986 §2.2), names that
// address on every route that takes an address from the path, and never the
// account named by the part after the "/".
func TestAddressWithSlashNamesItsOwnAccount(t *testing.T) {
	server := setupHTTPAPIServer(t)
	defer server.Close()
	ctx := context.Background()

	n := time.Now().UnixNano()
	slash := fmt.Sprintf("a/b-%d@example.com", n)              // the account the requests name
	other := fmt.Sprintf("b-%d@example.com", n)                // the part after the "/"
	slashAlias := fmt.Sprintf("x/c-%d@example.com", n)         // second credential of slash
	otherAlias := fmt.Sprintf("c-%d@example.com", n)           // second credential of other
	endpoint := fmt.Sprintf("q/credentials-%d@example.com", n) // the part after "/" looks like an endpoint

	for _, a := range []struct{ email, password string }{
		{slash, "slash-password"},
		{other, "other-password"},
		{endpoint, "endpoint-password"},
	} {
		resp, body := server.makeRequest(t, "POST", "/admin/accounts", adminapi.CreateAccountRequest{Email: a.email, Password: a.password})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s: %d - %s", a.email, resp.StatusCode, string(body))
		}
	}
	for _, c := range []struct{ primary, alias string }{{slash, slashAlias}, {other, otherAlias}} {
		resp, body := server.makeRequest(t, "POST", "/admin/accounts/"+url.PathEscape(c.primary)+"/credentials",
			adminapi.AddCredentialRequest{Email: c.alias, Password: "alias-password"})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("add credential %s to %s: %d - %s", c.alias, c.primary, resp.StatusCode, string(body))
		}
	}

	t.Run("GET account", func(t *testing.T) {
		for _, email := range []string{slash, endpoint} {
			resp, body := server.makeRequest(t, "GET", "/admin/accounts/"+url.PathEscape(email), nil)
			if resp.StatusCode != http.StatusOK {
				t.Errorf("GET /admin/accounts/%s: %d - %s", url.PathEscape(email), resp.StatusCode, string(body))
				continue
			}
			var got db.AccountDetails
			server.expectJSON(t, body, &got)
			if got.PrimaryEmail != email {
				t.Errorf("GET /admin/accounts/%s: primary_email %q, want %q", url.PathEscape(email), got.PrimaryEmail, email)
			}
		}
	})

	t.Run("GET credential", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/credentials/"+url.PathEscape(slash), nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /admin/credentials/%s: %d - %s", url.PathEscape(slash), resp.StatusCode, string(body))
		}
		var got db.CredentialDetails
		server.expectJSON(t, body, &got)
		if got.Address != slash {
			t.Errorf("GET /admin/credentials/%s: address %q, want %q", url.PathEscape(slash), got.Address, slash)
		}
	})

	t.Run("GET connections", func(t *testing.T) {
		resp, body := server.makeRequest(t, "GET", "/admin/connections/user/"+url.PathEscape(slash), nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /admin/connections/user/%s: %d - %s", url.PathEscape(slash), resp.StatusCode, string(body))
		}
		var got struct {
			Email string `json:"email"`
		}
		server.expectJSON(t, body, &got)
		if got.Email != slash {
			t.Errorf("GET /admin/connections/user/%s: email %q, want %q", url.PathEscape(slash), got.Email, slash)
		}
	})

	t.Run("PUT account", func(t *testing.T) {
		resp, body := server.makeRequest(t, "PUT", "/admin/accounts/"+url.PathEscape(slash), adminapi.UpdateAccountRequest{Password: "new-password"})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT /admin/accounts/%s: %d - %s", url.PathEscape(slash), resp.StatusCode, string(body))
		}
		if _, err := server.rdb.AuthenticateWithRetry(ctx, other, "other-password"); err != nil {
			t.Errorf("%s no longer signs in with its own password: %v", other, err)
		}
		if _, err := server.rdb.AuthenticateWithRetry(ctx, slash, "new-password"); err != nil {
			t.Errorf("%s does not sign in with the new password: %v", slash, err)
		}
	})

	t.Run("DELETE credential", func(t *testing.T) {
		resp, body := server.makeRequest(t, "DELETE", "/admin/credentials/"+url.PathEscape(slashAlias), nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("DELETE /admin/credentials/%s: %d - %s", url.PathEscape(slashAlias), resp.StatusCode, string(body))
		}
		if resp, body := server.makeRequest(t, "GET", "/admin/credentials/"+url.PathEscape(otherAlias), nil); resp.StatusCode != http.StatusOK {
			t.Errorf("credential %s of another account is gone: %d - %s", otherAlias, resp.StatusCode, string(body))
		}
		if resp, _ := server.makeRequest(t, "GET", "/admin/credentials/"+url.PathEscape(slashAlias), nil); resp.StatusCode != http.StatusNotFound {
			t.Errorf("credential %s still there after its DELETE: %d", slashAlias, resp.StatusCode)
		}
	})

	t.Run("DELETE account", func(t *testing.T) {
		resp, body := server.makeRequest(t, "DELETE", "/admin/accounts/"+url.PathEscape(slash), nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("DELETE /admin/accounts/%s: %d - %s", url.PathEscape(slash), resp.StatusCode, string(body))
		}
		for _, c := range []struct {
			email   string
			deleted bool
		}{{slash, true}, {other, false}} {
			result, err := server.rdb.AccountExistsWithRetry(ctx, c.email)
			if err != nil {
				t.Fatalf("AccountExists(%s): %v", c.email, err)
			}
			if !result.Exists || result.Deleted != c.deleted {
				t.Errorf("%s: exists %v, deleted %v; want exists, deleted %v", c.email, result.Exists, result.Deleted, c.deleted)
			}
		}
	})
}
