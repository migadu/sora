//go:build integration

package imapproxy_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/authcache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/integration_tests/common"
	soraserver "github.com/migadu/sora/server"
	"github.com/migadu/sora/server/credchanges"
	"github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/server/imapproxy"
)

// TestIMAPProxyCredentialChangesWithoutClusterOrAdminAPI changes credentials the way
// `sora-admin` does - straight in the database, with no connection tracker, no gossip
// and no Admin API to tell anyone - and expects the change to hold at the proxy and the
// backend once the node has read credential_changes: the old password is refused although
// the proxy's lookup cache and its persistent auth cache both held it, and the open
// session of a deleted account is ended.
func TestIMAPProxyCredentialChangesWithoutClusterOrAdminAPI(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	ctx := context.Background()

	backend, _ := common.SetupIMAPServerWithPROXY(t)
	defer backend.Close()
	rdb := backend.ResilientDB

	// The backend's own registry of sessions, as cmd/sora gives every backend: local
	// only, it tells no other node anything.
	tracker := soraserver.NewConnectionTracker("IMAP", "test", "localhost", "localhost-test", nil, 0, 0, 0, true)
	defer tracker.Stop()
	backend.Server.(*imap.IMAPServer).SetConnTracker(tracker)

	authCache, err := authcache.New(filepath.Join(t.TempDir(), "auth_cache.db"), time.Hour, time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("auth cache: %v", err)
	}
	rdb.SetAuthCache(authCache)
	t.Cleanup(func() {
		rdb.SetAuthCache(nil)
		authCache.Close()
	})

	proxyAddr := common.GetRandomAddress(t)
	proxy := setupIMAPProxyWithMasterAuthAndCache(t, rdb, proxyAddr, []string{backend.Address})
	proxyServer := proxy.Server.(*imapproxy.Server)
	defer proxyServer.Stop()

	watcher := credchanges.New(rdb.GetCredentialChangesSinceWithRetry, rdb.PruneCredentialChangesWithRetry, credchanges.Sinks{
		AuthCache: authCache,
		LoginCaches: func() []credchanges.LoginCache {
			return []credchanges.LoginCache{proxyServer.GetLookupCache(), backend.Server.(*imap.IMAPServer).GetLookupCache()}
		},
		Sessions: func() []credchanges.SessionEnder { return []credchanges.SessionEnder{tracker} },
	}, 0)
	if err := watcher.Refresh(ctx); err != nil {
		t.Fatalf("first read of credential_changes: %v", err)
	}

	login := func(t *testing.T, email, password string) (*imapclient.Client, error) {
		t.Helper()
		c, err := imapclient.DialInsecure(proxyAddr, nil)
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		if err := c.Login(email, password).Wait(); err != nil {
			c.Close()
			return nil, err
		}
		if _, err := c.Select("INBOX", nil).Wait(); err != nil {
			c.Close()
			return nil, err
		}
		t.Cleanup(func() { c.Close() })
		return c, nil
	}
	mustLogin := func(t *testing.T, email, password string) *imapclient.Client {
		t.Helper()
		c, err := login(t, email, password)
		if err != nil {
			t.Fatalf("login %s: %v", email, err)
		}
		return c
	}
	// Twice through the proxy: the first login is looked up in the database and fills
	// both caches, the second is answered from them.
	signInCached := func(t *testing.T, email, password string) {
		t.Helper()
		mustLogin(t, email, password).Logout().Wait()
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, _, err := authCache.Get(ctx, email); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the persistent auth cache never held %s", email)
			}
			time.Sleep(20 * time.Millisecond)
		}
		mustLogin(t, email, password).Logout().Wait()
	}
	newAccount := func(t *testing.T, tag string) common.TestAccount {
		email := fmt.Sprintf("credchanges-%s-%d@example.com", tag, time.Now().UnixNano())
		return common.CreateTestAccountWithEmail(t, rdb, email, "old-password-1!")
	}

	t.Run("PasswordChange", func(t *testing.T) {
		acct := newAccount(t, "password")
		signInCached(t, acct.Email, acct.Password)

		if err := rdb.UpdateAccountWithRetry(ctx, db.UpdateAccountRequest{
			Email: acct.Email, Password: "new-password-1!", HashType: "bcrypt",
		}); err != nil {
			t.Fatalf("change password: %v", err)
		}
		if err := watcher.Refresh(ctx); err != nil {
			t.Fatalf("read credential_changes: %v", err)
		}

		if c, err := login(t, acct.Email, acct.Password); err == nil {
			c.Close()
			t.Fatal("the old password still signs in through the proxy after the change was read")
		}
		mustLogin(t, acct.Email, "new-password-1!")
	})

	t.Run("AccountDeleted", func(t *testing.T) {
		acct := newAccount(t, "deleted")
		signInCached(t, acct.Email, acct.Password)
		open := mustLogin(t, acct.Email, acct.Password)

		if err := rdb.DeleteAccountWithRetry(ctx, acct.Email); err != nil {
			t.Fatalf("delete account: %v", err)
		}
		if err := watcher.Refresh(ctx); err != nil {
			t.Fatalf("read credential_changes: %v", err)
		}

		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := open.Select("INBOX", nil).Wait(); err != nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the deleted account's open session is still served")
			}
			time.Sleep(50 * time.Millisecond)
		}
		if _, _, err := authCache.Get(ctx, acct.Email); err != authcache.ErrCacheMiss {
			t.Errorf("the deleted account is still in the persistent auth cache: %v", err)
		}
		if c, err := login(t, acct.Email, acct.Password); err == nil {
			c.Close()
			t.Fatal("a deleted account still signs in through the proxy")
		}
	})
}
