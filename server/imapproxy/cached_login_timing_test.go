package imapproxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/lookupcache"
)

// TestFreshCachedLoginWrongPasswordCostsAVerification covers the lookup-cache side of
// #346. A wrong password for an address that logged in through this proxy within
// positive_revalidation_window is refused from the cache, without the database. A failed
// login for an unknown address costs a password verification, so that refusal must cost
// one as well, or a near-instant answer shows that the address has an account.
func TestFreshCachedLoginWrongPasswordCostsAVerification(t *testing.T) {
	// Cost 10 keeps one verification in the tens of milliseconds, far above the rest of
	// the cached path. The dummy hash follows BcryptCost.
	origCost := db.BcryptCost
	db.BcryptCost = 10
	t.Cleanup(func() { db.BcryptCost = origCost })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := &Server{
		name:                       "test",
		hostname:                   "test-host",
		ctx:                        ctx,
		cancel:                     cancel,
		activeSessions:             make(map[*Session]struct{}),
		connManager:                newTestConnManager(t, "127.0.0.1:1"),
		lookupCache:                newTestLookupCache(t),
		authLimiter:                &fakeAuthLimiter{},
		positiveRevalidationWindow: time.Minute,
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
	sess := newSession(srv, client)

	// One password verification, as a failed login for an unknown address pays. Load
	// only ever adds time, so the fastest of a few runs is the floor.
	db.DummyVerifyPassword("warm-up") // generates the dummy hash at this cost
	verification := time.Duration(1 << 62)
	for range 3 {
		start := time.Now()
		db.DummyVerifyPassword("wrong-password")
		verification = min(verification, time.Since(start))
	}

	start := time.Now()
	err := sess.authenticateUser("user@example.com", "wrong-password")
	elapsed := time.Since(start)
	if !errors.Is(err, consts.ErrAuthenticationFailed) {
		t.Fatalf("authenticateUser error = %v, want %v", err, consts.ErrAuthenticationFailed)
	}
	if elapsed < verification/2 {
		t.Fatalf("wrong password for a freshly cached login refused in %v; a failed login for an unknown address costs a password verification (%v), so the fast answer shows the address has an account", elapsed, verification)
	}
}
