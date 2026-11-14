//go:build integration

package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	serverPkg "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// remoteLookupProxyStack is the Admin API next to a proxy's connection tracker, on the
// database the backends use. A proxy keys a session that remote lookup authenticated by
// the ID derived from the address the lookup answered (proxy.DeriveAccountIDFromEmail),
// not by the database's account ID, even when the database holds the account: it
// registers the connection and its kick channel under that ID.
type remoteLookupProxyStack struct {
	api     *HTTPAPITestServer
	tracker *serverPkg.ConnectionTracker
	logins  *recordingLookupCache
}

func setupRemoteLookupProxyStack(t *testing.T, rdb *resilient.ResilientDatabase) *remoteLookupProxyStack {
	t.Helper()
	tracker := serverPkg.NewConnectionTracker("IMAP", "imap-proxy", "localhost", "node-1-imap-proxy", nil, 0, 0, 0, true)
	t.Cleanup(tracker.Stop)
	logins := &recordingLookupCache{}
	tracker.SetLookupCache(logins)
	api := startAdminAPI(t, rdb, map[string]*serverPkg.ConnectionTracker{"IMAP-node-1-imap-proxy": tracker})
	t.Cleanup(api.Close)
	return &remoteLookupProxyStack{api: api, tracker: tracker, logins: logins}
}

func (s *remoteLookupProxyStack) request(t *testing.T, method, endpoint string, body any, wantStatus int) {
	t.Helper()
	resp, respBody := s.api.makeRequest(t, method, endpoint, body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s %s: %d %s", method, endpoint, resp.StatusCode, respBody)
	}
}

// addAccount creates an account with a second address and returns both.
func (s *remoteLookupProxyStack) addAccount(t *testing.T, tag string) (primary, alias string) {
	t.Helper()
	primary = fmt.Sprintf("rl-kick-%s-%d@example.com", tag, time.Now().UnixNano())
	alias = "alias-" + primary
	s.request(t, "POST", "/admin/accounts", map[string]string{"email": primary, "password": "primary-password-1"}, http.StatusCreated)
	s.request(t, "POST", "/admin/accounts/"+primary+"/credentials",
		map[string]string{"email": alias, "password": "alias-password-2"}, http.StatusCreated)
	return primary, alias
}

// session registers a proxy session the way a proxy does for a login remote lookup
// answered with address, and returns its kick channel.
func (s *remoteLookupProxyStack) session(t *testing.T, address string) <-chan struct{} {
	t.Helper()
	return s.sessionUnder(t, proxy.DeriveAccountIDFromEmail(address), address)
}

// sessionUnder registers a session keyed by accountID and returns its kick channel.
func (s *remoteLookupProxyStack) sessionUnder(t *testing.T, accountID int64, address string) <-chan struct{} {
	t.Helper()
	const clientAddr = "192.0.2.10:50000"
	if err := s.tracker.RegisterConnection(context.Background(), accountID, address, "IMAP", clientAddr); err != nil {
		t.Fatal(err)
	}
	kicked := s.tracker.RegisterSession(accountID)
	t.Cleanup(func() {
		s.tracker.UnregisterSession(accountID, kicked)
		s.tracker.UnregisterConnection(context.Background(), accountID, "IMAP", clientAddr)
	})
	return kicked
}

func (s *remoteLookupProxyStack) kick(t *testing.T, address string, wantStatus int) {
	t.Helper()
	s.request(t, "POST", "/admin/connections/kick", map[string]string{"user_email": address}, wantStatus)
}

func ended(kicked <-chan struct{}) bool {
	select {
	case <-kicked:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

func stillOpen(kicked <-chan struct{}) bool {
	select {
	case <-kicked:
		return false
	default:
		return true
	}
}

// recordingLookupCache records the accounts a tracker drops the cached logins of.
type recordingLookupCache struct {
	mu       sync.Mutex
	accounts []int64
}

func (c *recordingLookupCache) InvalidateUser(serverName, username string) {}

func (c *recordingLookupCache) InvalidateAccount(accountID int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accounts = append(c.accounts, accountID)
}

func (c *recordingLookupCache) forgot(accountID int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Contains(c.accounts, accountID)
}

// POST /admin/connections/kick resolved an address the database holds to the database's
// account ID and kicked that ID only, so a proxy session remote lookup authenticated, keyed
// by the ID derived from the address the lookup answered, stayed open while the kick
// answered 200.
func TestAdminAPI_Kick_EndsRemoteLookupSessionsOfDatabaseAccount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	s := setupRemoteLookupProxyStack(t, common.SetupTestDatabase(t))

	for _, c := range []struct{ name, answered, named string }{
		{"the lookup answered the address the kick names", "primary", "primary"},
		{"the lookup answered the alias, the kick names the primary address", "alias", "primary"},
		{"the lookup answered the primary address, the kick names the alias", "primary", "alias"},
	} {
		t.Run(c.name, func(t *testing.T) {
			primary, alias := s.addAccount(t, "kick")
			addresses := map[string]string{"primary": primary, "alias": alias}
			kicked := s.session(t, addresses[c.answered])
			other, _ := s.addAccount(t, "bystander")
			bystander := s.session(t, other)

			s.kick(t, addresses[c.named], http.StatusOK)

			if !ended(kicked) {
				t.Errorf("the session remote lookup answered %s for is still open after the kick of %s", addresses[c.answered], addresses[c.named])
			}
			if !stillOpen(bystander) {
				t.Errorf("the kick of %s ended another account's session", addresses[c.named])
			}
		})
	}

	t.Run("an address the database does not know is kicked by its derived ID", func(t *testing.T) {
		address := fmt.Sprintf("rl-kick-lookup-only-%d@example.org", time.Now().UnixNano())
		kicked := s.session(t, address)
		s.kick(t, address, http.StatusOK)
		if !ended(kicked) {
			t.Error("the remote lookup session is still open after the kick")
		}
	})
}

// Deleting or purging an account ended its sessions under the database's account ID
// only, and a password change or a removed credential dropped the cached logins under it
// only: a remote lookup session and the proxy's cached lookup answer, both keyed by the
// derived ID, outlived the change.
func TestAdminAPI_AccountChanges_ReachRemoteLookupSessions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	s := setupRemoteLookupProxyStack(t, common.SetupTestDatabase(t))

	t.Run("delete ends the sessions", func(t *testing.T) {
		primary, alias := s.addAccount(t, "delete")
		byPrimary, byAlias := s.session(t, primary), s.session(t, alias)
		s.request(t, "DELETE", "/admin/accounts/"+primary, nil, http.StatusOK)
		if !ended(byPrimary) || !ended(byAlias) {
			t.Error("a remote lookup session of the deleted account is still open")
		}
	})

	t.Run("purge ends the sessions", func(t *testing.T) {
		primary, alias := s.addAccount(t, "purge")
		byPrimary, byAlias := s.session(t, primary), s.session(t, alias)
		s.request(t, "DELETE", "/admin/accounts/"+alias+"?purge=true", nil, http.StatusAccepted)
		if !ended(byPrimary) || !ended(byAlias) {
			t.Error("a remote lookup session of the purged account is still open")
		}
	})

	t.Run("password change drops the cached logins", func(t *testing.T) {
		primary, alias := s.addAccount(t, "password")
		s.request(t, "PUT", "/admin/accounts/"+primary, map[string]string{"password": "new-password-3"}, http.StatusOK)
		for _, address := range []string{primary, alias} {
			if !s.logins.forgot(proxy.DeriveAccountIDFromEmail(address)) {
				t.Errorf("the cached remote lookup login of %s was kept", address)
			}
		}
	})

	t.Run("credential removal drops the cached logins", func(t *testing.T) {
		_, alias := s.addAccount(t, "credential")
		s.request(t, "DELETE", "/admin/credentials/"+alias, nil, http.StatusOK)
		if !s.logins.forgot(proxy.DeriveAccountIDFromEmail(alias)) {
			t.Errorf("the cached remote lookup login of the removed %s was kept", alias)
		}
	})
}

// POST /admin/connections/kick took any failure of the account lookup for "not in the
// database": with the database unreachable it kicked the ID derived from the address,
// which no session of a database account is keyed by, and answered 200.
func TestAdminAPI_Kick_DatabaseFailureIsAnError(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	t.Cleanup(outage.End)
	s := setupRemoteLookupProxyStack(t, rdb)

	primary, _ := s.addAccount(t, "outage")
	accountID, err := rdb.GetAccountIDByEmailWithRetry(context.Background(), primary)
	if err != nil {
		t.Fatal(err)
	}
	byDatabaseID := s.sessionUnder(t, accountID, primary)
	byDerivedID := s.session(t, primary)

	outage.Begin()
	s.kick(t, primary, http.StatusInternalServerError)

	if !stillOpen(byDatabaseID) || !stillOpen(byDerivedID) {
		t.Error("a kick that answered an error ended a session")
	}
}
