package pop3proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// unclassifiedErrorLookup is a remote lookup whose every query fails with an error that
// is neither proxy.ErrRemoteLookupTransient nor a verdict on the user.
type unclassifiedErrorLookup struct{}

func (unclassifiedErrorLookup) fail() (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return nil, proxy.AuthFailed, errors.New("lookup request could not be built")
}

func (l unclassifiedErrorLookup) LookupUserRoute(context.Context, string, string) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return l.fail()
}

func (l unclassifiedErrorLookup) LookupUserRouteWithOptions(context.Context, string, string, bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return l.fail()
}

func (l unclassifiedErrorLookup) LookupUserRouteWithClientIP(context.Context, string, string, string, bool) (*proxy.UserRoutingInfo, proxy.AuthResult, error) {
	return l.fail()
}

func (unclassifiedErrorLookup) Close() error { return nil }

// knownUserAuthCache is the persistent auth cache of a proxy that has already logged
// this user in from the database, so a database login needs no PostgreSQL.
type knownUserAuthCache struct{ hash string }

func (c knownUserAuthCache) Get(context.Context, string) (int64, string, error) {
	return 42, c.hash, nil
}
func (knownUserAuthCache) Put(context.Context, string, int64, string) error { return nil }
func (knownUserAuthCache) Invalidate(context.Context, string) error         { return nil }
func (knownUserAuthCache) InvalidateAccount(context.Context, int64) error   { return nil }

// TestPOP3ProxyUnclassifiedLookupErrorIsATemporaryFailure (#518): with
// lookup_local_users = false the remote lookup is the only authority, so a lookup error
// of any kind is a temporary failure (-ERR [SYS/TEMP]), like an outage. An error the
// proxy could not classify used to fall through to the database: on a node without one
// the session panicked, on a node with one the user was logged in from it.
func TestPOP3ProxyUnclassifiedLookupErrorIsATemporaryFailure(t *testing.T) {
	hash, err := db.GenerateBcryptHash("secret")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	knowsUser := &resilient.ResilientDatabase{}
	knowsUser.SetAuthCache(knownUserAuthCache{hash: hash})

	for _, c := range []struct {
		name string
		rdb  *resilient.ResilientDatabase
	}{
		{"no database", nil},
		{"database that knows the user", knowsUser},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			connManager, err := proxy.NewConnectionManagerWithRouting([]string{"127.0.0.1:1"}, 110, false, false, false, 200*time.Millisecond, unclassifiedErrorLookup{}, "test")
			if err != nil {
				t.Fatalf("failed to create connection manager: %v", err)
			}
			limiter := &verdictlessLimiter{}
			srv := &POP3ProxyServer{
				name:                       "test",
				hostname:                   "test-host",
				appCtx:                     ctx,
				cancel:                     cancel,
				connManager:                connManager,
				lookupCache:                newPOP3TestLookupCache(t),
				authLimiter:                limiter,
				positiveRevalidationWindow: 30 * time.Second,
				activeSessions:             make(map[*POP3ProxySession]struct{}),
				rdb:                        c.rdb,
				remotelookupConfig:         &config.RemoteLookupConfig{Enabled: true, LookupLocalUsers: false},
			}

			client, remote := net.Pipe()
			defer client.Close()
			defer remote.Close()
			sess := &POP3ProxySession{server: srv, clientConn: remote, listenerConn: remote, ctx: ctx, cancel: cancel}

			err = func() (err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("panic: %v", r)
					}
				}()
				return sess.authenticate("user@example.com", "secret")
			}()
			if !errors.Is(err, server.ErrAuthServiceUnavailable) {
				t.Fatalf("login after an unclassified lookup error: %v, want %v", err, server.ErrAuthServiceUnavailable)
			}
			if n := limiter.failures.Load(); n != 0 {
				t.Errorf("%d failed login(s) recorded in the auth rate limiter for a lookup error, want 0", n)
			}
		})
	}
}
