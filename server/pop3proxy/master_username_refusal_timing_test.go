package pop3proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/testutils"
	"golang.org/x/crypto/bcrypt"
)

const testMasterUsername, testMasterPassword = "masteruser", "master-secret"

// refuseTwiceAs logs in twice as username with password, each on a fresh session of srv,
// and returns what that leaves behind (lookups is the caller's). A refusal is recorded as
// the reply the client gets: every error that is not a temporary failure is answered
// "Authentication failed", whatever it wraps.
func refuseTwiceAs(t *testing.T, srv *POP3ProxyServer, username, password string) lookupRefusal {
	t.Helper()
	limiter := &successKeyLimiter{}
	srv.authLimiter = limiter

	var out lookupRefusal
	for i := range out.errs {
		client, remote := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		sess := &POP3ProxySession{server: srv, clientConn: remote, listenerConn: remote, ctx: ctx, cancel: cancel}
		before := testutils.PasswordVerifications()
		err := sess.authenticate(username, password)
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
	out.successKeys = strings.Join(limiter.successKeys, ",")
	_, out.cached = srv.lookupCache.Get(srv.name, username)
	return out
}

// successKeyLimiter is verdictlessLimiter that also keeps the key of every success
// recorded.
type successKeyLimiter struct {
	verdictlessLimiter
	mu          sync.Mutex
	successKeys []string
}

func (l *successKeyLimiter) RecordAuthAttemptWithProxy(ctx context.Context, conn net.Conn, proxyInfo *server.ProxyProtocolInfo, key string, success bool) {
	l.verdictlessLimiter.RecordAuthAttemptWithProxy(ctx, conn, proxyInfo, key, success)
	if success {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.successKeys = append(l.successKeys, key)
	}
}

// TestPOP3ProxyWrongMasterPasswordLooksLikeAnotherSuffix (#801): a wrong password in the
// master username form "user@domain.com@MASTERUSER" is refused like a wrong password
// under any other suffix: after one lookup and one password verification, cached, and
// answered from the cache when repeated. The proxy used to compare the master password
// and refuse at once, so the response time confirmed a guessed master username. The
// account's own password logs in through the master form as through any other suffix,
// its success recorded under the account's key, not the master credential's (#949).
// Verifications are counted, not timed (#782).
func TestPOP3ProxyWrongMasterPasswordLooksLikeAnotherSuffix(t *testing.T) {
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
		work   [2]int
	}{
		{"known_address", func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{"address": "anna@example.com", "password_hash": hash})
		}, [2]int{1, 0}},
		{"unknown_address", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }, [2]int{1, 0}},
		{"suffix_specific_refusal", func(w http.ResponseWriter, r *http.Request) {
			if strings.Count(r.URL.Query().Get("email"), "@") > 1 {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"address": "anna@example.com", "password_hash": hash})
		}, [2]int{1, 0}},
		{"suffix_specific_unavailable", func(w http.ResponseWriter, r *http.Request) {
			if strings.Count(r.URL.Query().Get("email"), "@") > 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"address": "anna@example.com", "password_hash": hash})
		}, [2]int{0, 0}},
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
				srv, err := New(context.Background(), "localhost", "127.0.0.1:0", &resilient.ResilientDatabase{}, POP3ProxyServerOptions{
					Name: "master-refusal", RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
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
			wantLookups, wantCached, wantFailures := int32(1), true, int32(2)
			if lookup.name == "suffix_specific_unavailable" {
				wantLookups, wantCached, wantFailures = 2, false, 0
			}
			if other.verifications != lookup.work || other.lookups != wantLookups || other.cached != wantCached || other.failures != wantFailures {
				t.Fatalf("wrong password under another suffix: %+v; want work=%v lookups=%d cached=%v failures=%d", other, lookup.work, wantLookups, wantCached, wantFailures)
			}
			if got := refuse("anna@example.com@"+testMasterUsername, "wrong-password"); got != other {
				t.Errorf("wrong password under the master suffix: %+v\nunder another suffix: %+v", got, other)
			}

			// The account's own password, accepted by the lookup service for a known
			// address, logs in under the master suffix as under any other (#949).
			own := refuse("anna@example.com@other", "own-password")
			if lookup.name == "known_address" && own.successKeys != "anna@example.com,anna@example.com" {
				t.Fatalf("own password under another suffix: %+v; want two successes recorded under the account's key", own)
			}
			if got := refuse("anna@example.com@"+testMasterUsername, "own-password"); got != own {
				t.Errorf("own password under the master suffix: %+v\nunder another suffix: %+v", got, own)
			}
		})
	}
}
