//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
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

	// The sub-routes after {email} were path-sniffed before; now each is its own
	// pattern, so each must still take the whole escaped segment as the address.
	t.Run("account sub-routes", func(t *testing.T) {
		base := "/admin/accounts/" + url.PathEscape(slash)
		for _, c := range []struct {
			method, path string
			body         any
		}{
			{"GET", base + "/exists", nil},
			{"GET", base + "/credentials", nil},
			{"GET", base + "/messages/deleted", nil},
			{"POST", base + "/messages/restore", map[string]string{"mailbox": "INBOX"}},
		} {
			resp, body := server.makeRequest(t, c.method, c.path, c.body)
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s %s: %d - %s", c.method, c.path, resp.StatusCode, string(body))
				continue
			}
			var got struct {
				Email       string `json:"email"`
				Exists      *bool  `json:"exists"`
				Credentials []struct {
					Address string
				} `json:"credentials"`
			}
			server.expectJSON(t, body, &got)
			if got.Email != slash {
				t.Errorf("%s %s: email %q, want %q", c.method, c.path, got.Email, slash)
			}
			if got.Exists != nil && !*got.Exists {
				t.Errorf("%s %s: exists false", c.method, c.path)
			}
			if strings.HasSuffix(c.path, "/credentials") {
				var addrs []string
				for _, cr := range got.Credentials {
					addrs = append(addrs, cr.Address)
				}
				if !slices.Contains(addrs, slashAlias) || slices.Contains(addrs, otherAlias) {
					t.Errorf("%s %s: credentials %q, want %s and not %s", c.method, c.path, addrs, slashAlias, otherAlias)
				}
			}
		}
	})

	// A client that does not encode the "/" sends two segments: no route takes
	// them, and the account after the "/" is left alone.
	t.Run("unencoded slash", func(t *testing.T) {
		for _, method := range []string{"GET", "DELETE"} {
			resp, body := server.makeRequest(t, method, "/admin/accounts/"+slash, nil)
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("%s /admin/accounts/%s: %d - %s, want 404", method, slash, resp.StatusCode, string(body))
			}
		}
		result, err := server.rdb.AccountExistsWithRetry(ctx, other)
		if err != nil {
			t.Fatalf("AccountExists(%s): %v", other, err)
		}
		if !result.Exists || result.Deleted {
			t.Errorf("%s: exists %v, deleted %v; want exists, not deleted", other, result.Exists, result.Deleted)
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

	t.Run("POST restore", func(t *testing.T) {
		resp, body := server.makeRequest(t, "POST", "/admin/accounts/"+url.PathEscape(slash)+"/restore", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("POST /admin/accounts/%s/restore: %d - %s", url.PathEscape(slash), resp.StatusCode, string(body))
		}
		result, err := server.rdb.AccountExistsWithRetry(ctx, slash)
		if err != nil {
			t.Fatalf("AccountExists(%s): %v", slash, err)
		}
		if !result.Exists || result.Deleted {
			t.Errorf("%s: exists %v, deleted %v after restore; want exists, not deleted", slash, result.Exists, result.Deleted)
		}
	})
}
