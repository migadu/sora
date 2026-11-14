//go:build integration

package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/proxy"
)

// userConnections returns the entries GET /admin/connections/user/{address} lists.
func (s *accountLoginsStack) userConnections(t *testing.T, address string) []map[string]any {
	t.Helper()
	resp, body := s.api.makeRequest(t, "GET", "/admin/connections/user/"+address, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/connections/user/%s: %d %s", address, resp.StatusCode, body)
	}
	var result struct {
		Connections []map[string]any `json:"connections"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("GET /admin/connections/user/%s: %v: %s", address, err, body)
	}
	return result.Connections
}

// GET /admin/connections/user/{email} lists the account's sessions whichever of its
// addresses names it, as POST /admin/connections/kick ends them. The tracker keeps one
// entry per account with the address of the session that created it, and the handler
// compared the path with that address only, so an account was not found under its other
// addresses.
func TestAdminAPI_UserConnections_FindsAccountUnderAnyAddress(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	s := setupAccountLoginsStack(t)

	const password, aliasPassword = "primary-password-1", "alias-password-2"
	// addAccount creates an account with a second address and returns both.
	addAccount := func(tag string) (primary, alias string) {
		primary = s.createAccount(t, tag, password)
		alias = "alias-" + primary
		s.request(t, "POST", "/admin/accounts/"+primary+"/credentials",
			map[string]string{"email": alias, "password": aliasPassword}, http.StatusCreated)
		return primary, alias
	}
	// listed fails unless address lists exactly one entry, the session's, and returns it.
	listed := func(t *testing.T, address, loginAddress string) map[string]any {
		t.Helper()
		conns := s.userConnections(t, address)
		if len(conns) != 1 {
			t.Fatalf("%s: listed %d entries, want the session logged in as %s: %v", address, len(conns), loginAddress, conns)
		}
		if conns[0]["email"] != loginAddress || conns[0]["local_count"] != float64(1) {
			t.Errorf("%s: entry %v, want the one session logged in as %s", address, conns[0], loginAddress)
		}
		return conns[0]
	}

	primary, alias := addAccount("by-primary")
	byPrimary := s.mustLogin(t, primary, password)
	aliasPrimary, aliasAlias := addAccount("by-alias")
	s.mustLogin(t, aliasAlias, aliasPassword)

	t.Run("session under the primary address, named by the alias", func(t *testing.T) {
		got := listed(t, alias, primary)
		if want := listed(t, primary, primary); got["account_id"] != want["account_id"] {
			t.Errorf("account_id %v under the alias, %v under the primary address", got["account_id"], want["account_id"])
		}
	})

	t.Run("session under the alias, named by the primary address", func(t *testing.T) {
		listed(t, aliasPrimary, aliasAlias)
		listed(t, aliasAlias, aliasAlias)
	})

	t.Run("an address of another account lists nothing", func(t *testing.T) {
		other := s.createAccount(t, "other", password)
		if conns := s.userConnections(t, other); len(conns) != 0 {
			t.Errorf("%s has no session, listed %v", other, conns)
		}
	})

	t.Run("a remote lookup account is found under its address", func(t *testing.T) {
		// A proxy keys a remote lookup account by an ID derived from the address the
		// lookup answered, and the database does not know the address.
		const address = "remote-lookup-user@example.org"
		accountID := proxy.DeriveAccountIDFromEmail(address)
		if err := s.tracker.RegisterConnection(context.Background(), accountID, address, "IMAP", "192.0.2.1:50000"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.tracker.UnregisterConnection(context.Background(), accountID, "IMAP", "192.0.2.1:50000") })
		listed(t, address, address)
	})

	// The usual remote lookup deployment: the lookup service answers for accounts the
	// Admin API's database holds too (the backends' database), and the proxy still keys
	// the session by the ID derived from the address the lookup answered, with that
	// address. The database account ID matches no such entry, so the account's other
	// addresses must name it.
	rlPrimary, rlAlias := addAccount("remote-lookup")
	for _, c := range []struct{ name, answered, named string }{
		{"the lookup answered the primary address, named by the alias", rlPrimary, rlAlias},
		{"the lookup answered the alias, named by the primary address", rlAlias, rlPrimary},
	} {
		t.Run("remote lookup session in the database: "+c.name, func(t *testing.T) {
			accountID := proxy.DeriveAccountIDFromEmail(c.answered)
			if err := s.tracker.RegisterConnection(context.Background(), accountID, c.answered, "IMAP", "192.0.2.2:50000"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.tracker.UnregisterConnection(context.Background(), accountID, "IMAP", "192.0.2.2:50000") })
			if got := listed(t, c.named, c.answered); got["account_id"] != float64(accountID) {
				t.Errorf("account_id %v, want the derived ID %d the proxy keys the session by", got["account_id"], accountID)
			}
		})
	}

	t.Run("simultaneous remote lookup addresses are all listed", func(t *testing.T) {
		wanted := make(map[float64]bool)
		for _, address := range []string{rlPrimary, rlAlias} {
			id := proxy.DeriveAccountIDFromEmail(address)
			wanted[float64(id)] = true
			if err := s.tracker.RegisterConnection(context.Background(), id, address, "IMAP", "192.0.2.3:50000"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.tracker.UnregisterConnection(context.Background(), id, "IMAP", "192.0.2.3:50000") })
		}
		for _, address := range []string{rlPrimary, rlAlias} {
			entries := s.userConnections(t, address)
			if len(entries) != len(wanted) {
				t.Fatalf("%s listed %d entries, want both remote lookup IDs: %v", address, len(entries), entries)
			}
			seen := make(map[float64]bool)
			for _, entry := range entries {
				id := entry["account_id"].(float64)
				if !wanted[id] || seen[id] {
					t.Errorf("%s listed unexpected or duplicate account ID: %v", address, entry)
				}
				seen[id] = true
			}
		}
	})

	t.Run("kick under the alias ends the session listed under it", func(t *testing.T) {
		s.request(t, "POST", "/admin/connections/kick", map[string]string{"user_email": alias}, http.StatusOK)
		waitClosed(t, byPrimary, "the session the alias names")
	})
}
