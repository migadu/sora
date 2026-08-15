package lookupcache

import (
	"context"
	"sync"
	"testing"
	"time"
)

// withVerifyPassword swaps the password-verification seam for one test.
func withVerifyPassword(t *testing.T, fn func(hashedPassword, password string) error) {
	t.Helper()
	orig := verifyPassword
	verifyPassword = fn
	t.Cleanup(func() { verifyPassword = orig })
}

// TestAuthenticateReleasesLockDuringVerify asserts Authenticate does not hold c.mu
// across password verification. Verification is bcrypt (~180ms at cost 12), so
// holding the read lock across it makes every cache write wait it out, and Go's
// RWMutex parks new readers behind a waiting writer - convoying the entire auth
// path on exactly the reconnect storm this cache exists to absorb.
func TestAuthenticateReleasesLockDuringVerify(t *testing.T) {
	cache := New(time.Minute, time.Minute, 100, time.Minute, time.Minute)
	t.Cleanup(func() { _ = cache.Stop(context.Background()) })

	const (
		address  = "user@example.com"
		password = "secret"
	)

	var (
		signalOnce  sync.Once
		releaseOnce sync.Once
	)
	inVerify := make(chan struct{})
	releaseVerify := make(chan struct{})
	release := func() { releaseOnce.Do(func() { close(releaseVerify) }) }
	t.Cleanup(release)

	withVerifyPassword(t, func(hashedPassword, pw string) error {
		signalOnce.Do(func() { close(inVerify) })
		<-releaseVerify
		return nil
	})

	cache.SetSuccess(address, 42, "cached-hash", password)

	authDone := make(chan struct{})
	go func() {
		defer close(authDone)
		cache.Authenticate(address, password)
	}()

	<-inVerify // verification is now in flight

	// A cache write must not have to wait out the in-flight verification.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		cache.SetSuccess("other@example.com", 43, "other-hash", "other-pass")
	}()

	select {
	case <-writerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("cache write blocked 5s behind an in-flight password verification: Authenticate holds c.mu across verifyPassword")
	}

	// ...and an unrelated reader must not be convoyed behind that pending write.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		cache.Authenticate("third@example.com", "whatever") // cache miss: read path only
	}()

	select {
	case <-readerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("unrelated reader blocked 5s while a password verification was in flight")
	}

	release()
	<-authDone
}

// TestAuthenticateSucceedsOnFreshEntry guards the fix against regressing the
// contract itself: a fresh positive entry whose verification passes must still
// authenticate, and one whose verification fails must invalidate and miss.
func TestAuthenticateSucceedsOnFreshEntry(t *testing.T) {
	const (
		address  = "user@example.com"
		password = "secret"
	)

	t.Run("verify ok", func(t *testing.T) {
		cache := New(time.Minute, time.Minute, 100, time.Minute, time.Minute)
		t.Cleanup(func() { _ = cache.Stop(context.Background()) })
		withVerifyPassword(t, func(hashedPassword, pw string) error {
			if hashedPassword != "cached-hash" || pw != password {
				t.Errorf("verify got (%q, %q), want (%q, %q)", hashedPassword, pw, "cached-hash", password)
			}
			return nil
		})

		cache.SetSuccess(address, 42, "cached-hash", password)

		accountID, found, err := cache.Authenticate(address, password)
		if err != nil {
			t.Fatalf("Authenticate returned error: %v", err)
		}
		if !found {
			t.Fatal("expected cache hit with successful authentication")
		}
		if accountID != 42 {
			t.Fatalf("accountID = %d, want 42", accountID)
		}
	})

	t.Run("verify fails invalidates", func(t *testing.T) {
		cache := New(time.Minute, time.Minute, 100, time.Minute, time.Minute)
		t.Cleanup(func() { _ = cache.Stop(context.Background()) })
		withVerifyPassword(t, func(hashedPassword, pw string) error {
			return context.DeadlineExceeded // any verification failure
		})

		cache.SetSuccess(address, 42, "cached-hash", password)

		accountID, found, err := cache.Authenticate(address, password)
		if err != nil {
			t.Fatalf("Authenticate returned error: %v", err)
		}
		if found || accountID != 0 {
			t.Fatalf("expected miss on verification failure, got (%d, %v)", accountID, found)
		}

		cache.mu.RLock()
		_, stillCached := cache.entries[address]
		cache.mu.RUnlock()
		if stillCached {
			t.Fatal("expected entry to be invalidated after verification failure")
		}
	})
}
