package imapproxy

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

// TestIMAPProxyUnclassifiedLookupErrorIsATemporaryFailure (#518): with
// lookup_local_users = false the remote lookup is the only authority, so a lookup error
// of any kind is a temporary failure (NO [UNAVAILABLE]), like an outage. An error the
// proxy could not classify used to fall through to the database: on a node without one
// the session panicked, on a node with one the user was logged in from it.
func TestIMAPProxyUnclassifiedLookupErrorIsATemporaryFailure(t *testing.T) {
	hash, err := db.GenerateBcryptHash("secret")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}
	knowsUser := &resilient.ResilientDatabase{}
	knowsUser.SetAuthCache(&stubAuthCache{accountID: 42, hash: hash})

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
			connManager, err := proxy.NewConnectionManagerWithRouting([]string{"127.0.0.1:1"}, 143, false, false, false, 200*time.Millisecond, unclassifiedErrorLookup{}, "test")
			if err != nil {
				t.Fatalf("failed to create connection manager: %v", err)
			}
			limiter := &failureCountingLimiter{}
			srv := &Server{
				name:                       "test",
				hostname:                   "test-host",
				ctx:                        ctx,
				cancel:                     cancel,
				activeSessions:             make(map[*Session]struct{}),
				connManager:                connManager,
				lookupCache:                newTestLookupCache(t),
				authLimiter:                limiter,
				positiveRevalidationWindow: 30 * time.Second,
				rdb:                        c.rdb,
				remotelookupConfig:         &config.RemoteLookupConfig{Enabled: true, LookupLocalUsers: false},
			}

			client, remote := net.Pipe()
			defer client.Close()
			defer remote.Close()

			err = func() (err error) {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("panic: %v", r)
					}
				}()
				return newSession(srv, remote).authenticateUser("user@example.com", "secret")
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
