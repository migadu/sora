package managesieveproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/testutils"
	"golang.org/x/crypto/bcrypt"
)

const testMasterUsername, testMasterPassword = "masteruser", "master-secret"

// refuseTwiceAs logs in twice as username with password, each on a fresh session of srv,
// and returns what that leaves behind (lookups is the caller's). A refusal is recorded as
// the reply the client gets: every error that is not a temporary failure is answered
// "Authentication failed", whatever it wraps.
func refuseTwiceAs(t *testing.T, srv *Server, username, password string) lookupRefusal {
	t.Helper()
	limiter := &verdictlessLimiter{}
	srv.authLimiter = limiter

	var out lookupRefusal
	for i := range out.errs {
		client, remote := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		sess := &Session{server: srv, clientConn: remote, listenerConn: remote, ctx: ctx, cancel: cancel}
		before := testutils.PasswordVerifications()
		err := sess.authenticateUser(username, password, time.Now())
		out.verifications[i] = testutils.PasswordVerifications() - before
		cancel()
		out.errs[i] = fmt.Sprint(err)
		if errors.Is(err, consts.ErrAuthenticationFailed) {
			out.errs[i] = consts.ErrAuthenticationFailed.Error()
		}
		client.Close()
		remote.Close()
	}
	out.failures = limiter.failures.Load()
	_, out.cached = srv.lookupCache.Get(srv.name, username)
	return out
}

// TestManageSieveProxyWrongMasterPasswordLooksLikeAnotherSuffix (#801): a wrong password in the
// master username form "user@domain.com@MASTERUSER" is refused like a wrong password
// under any other suffix: after one lookup and one password verification, cached, and
// answered from the cache when repeated. The proxy used to compare the master password
// and refuse at once, so the response time confirmed a guessed master username. The
// account's own password does not log in through the master form, but it is refused at
// the same cost. Verifications are counted, not timed (#782).
func TestManageSieveProxyWrongMasterPasswordLooksLikeAnotherSuffix(t *testing.T) {
	origCost := db.BcryptCost
	db.BcryptCost = bcrypt.MinCost
	t.Cleanup(func() { db.BcryptCost = origCost })

	hash, err := db.GenerateBcryptHash("own-password")
	if err != nil {
		t.Fatalf("GenerateBcryptHash: %v", err)
	}

	for _, lookup := range []struct {
		name   string
		answer http.HandlerFunc
	}{
		{"known_address", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{"address": "anna@example.com", "password_hash": hash})
		}},
		{"unknown_address", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }},
	} {
		t.Run(lookup.name, func(t *testing.T) {
			refuse := func(username, password string) lookupRefusal {
				var lookups atomic.Int32
				lookupSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					lookups.Add(1)
					lookup.answer(w, r)
				}))
				defer lookupSrv.Close()

				// lookup_local_users is off: the lookup service is authoritative.
				srv, err := New(context.Background(), &resilient.ResilientDatabase{}, "localhost", ServerOptions{
					Name: "master-refusal", Addr: "127.0.0.1:0", RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
					InsecureAuth:   true,
					MasterUsername: testMasterUsername,
					MasterPassword: testMasterPassword,
					RemoteLookup:   &config.RemoteLookupConfig{Enabled: true, URL: lookupSrv.URL + "/lookup?email=$email", Timeout: "2s"},
				})
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				defer srv.Stop()

				out := refuseTwiceAs(t, srv, username, password)
				out.lookups = lookups.Load()
				return out
			}

			other := refuse("anna@example.com@other", "wrong-password")
			if other.verifications != [2]int{1, 0} || other.lookups != 1 || !other.cached {
				t.Fatalf("wrong password under another suffix: %+v; want one verification, one lookup and a cached refusal", other)
			}
			for _, password := range []string{"wrong-password", "own-password"} {
				if got := refuse("anna@example.com@"+testMasterUsername, password); got != other {
					t.Errorf("%q under the master suffix: %+v\nwrong password under another suffix: %+v", password, got, other)
				}
			}
		})
	}
}
