package managesieveproxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
	"github.com/migadu/sora/testutils"
	"golang.org/x/crypto/bcrypt"
)

// TestFreshCachedLoginWrongPasswordCostsAVerification covers the lookup-cache side of
// #346. A wrong password for an address that logged in through this proxy within
// positive_revalidation_window is refused from the cache, without the database. A failed
// login for an unknown address costs a password verification, so that refusal must cost
// one as well, or a near-instant answer shows that the address has an account.
func TestFreshCachedLoginWrongPasswordCostsAVerification(t *testing.T) {
	// The verifications are counted, not timed (#782): a wall-clock floor calibrated
	// under CPU contention fails a correct refusal that runs after the contention eases.
	// The dummy hash follows BcryptCost, so the cheapest cost keeps the test fast.
	origCost := db.BcryptCost
	db.BcryptCost = bcrypt.MinCost
	t.Cleanup(func() { db.BcryptCost = origCost })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connManager, err := proxy.NewConnectionManager([]string{"127.0.0.1:1"}, 4190, false, false, false, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("failed to create connection manager: %v", err)
	}
	srv := &Server{
		name:                       "test",
		hostname:                   "test-host",
		ctx:                        ctx,
		cancel:                     cancel,
		connManager:                connManager,
		lookupCache:                newMSTestLookupCache(t),
		authLimiter:                (*server.AuthRateLimiter)(nil), // rate limiting disabled
		positiveRevalidationWindow: time.Minute,
		activeSessions:             make(map[*Session]struct{}),
	}
	// The user logged in with "secret" a moment ago.
	srv.lookupCache.Set(srv.name, "user@example.com", &lookupcache.CacheEntry{
		AccountID:      42,
		PasswordDigest: lookupcache.NewPasswordDigest("secret"),
		Result:         lookupcache.AuthSuccess,
	})

	client, remote := net.Pipe()
	defer client.Close()
	defer remote.Close()
	sess := &Session{server: srv, clientConn: client, listenerConn: client, ctx: ctx, cancel: cancel}

	before := testutils.PasswordVerifications()
	err = sess.authenticateUser("user@example.com", "wrong-password", time.Now())
	verifications := testutils.PasswordVerifications() - before
	if !errors.Is(err, consts.ErrAuthenticationFailed) {
		t.Fatalf("authenticateUser error = %v, want %v", err, consts.ErrAuthenticationFailed)
	}
	if verifications != 1 {
		t.Fatalf("wrong password for a freshly cached login refused after %d password verifications; a failed login for an unknown address costs one, so a different cost shows the address has an account", verifications)
	}
}
