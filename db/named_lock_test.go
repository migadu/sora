package db

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// These locks fence work that must happen on exactly one node. Gossip leader election has
// no quorum, so a partition elects a leader on both sides; the database cannot be
// partitioned into two writable copies, which is the whole reason the fence lives here.

func TestNamedLockIsMutuallyExclusive(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	ctx := context.Background()
	database := setupTestDatabase(t)
	defer database.Close()

	name := fmt.Sprintf("test-lock-%d", time.Now().UnixNano())

	first, err := database.TryAcquireNamedLock(ctx, name, time.Minute)
	require.NoError(t, err)
	require.NotNil(t, first, "the first acquire must take the lock")

	second, err := database.TryAcquireNamedLock(ctx, name, time.Minute)
	require.NoError(t, err)
	require.Nil(t, second, "a second node took a lock that is already held: two partitioned "+
		"leaders would both order a certificate for the same domain")

	// Releasing hands it straight on, without waiting out the ttl.
	require.NoError(t, database.ReleaseNamedLock(ctx, first))

	third, err := database.TryAcquireNamedLock(ctx, name, time.Minute)
	require.NoError(t, err)
	require.NotNil(t, third, "a released lock must be immediately available")
	require.NoError(t, database.ReleaseNamedLock(ctx, third))
}

// TestNamedLockExpiryIsTakenOver covers the holder that died mid-work: the claim has to
// lapse on its own, or one crash would stop certificate issuance permanently.
func TestNamedLockExpiryIsTakenOver(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	ctx := context.Background()
	database := setupTestDatabase(t)
	defer database.Close()

	name := fmt.Sprintf("test-lock-expiry-%d", time.Now().UnixNano())

	// A claim that is already expired stands in for a node that crashed while holding it.
	dead, err := database.TryAcquireNamedLock(ctx, name, time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, dead)

	require.Eventually(t, func() bool {
		taken, err := database.TryAcquireNamedLock(ctx, name, time.Minute)
		if err != nil || taken == nil {
			return false
		}
		require.NoError(t, database.ReleaseNamedLock(ctx, taken))
		return true
	}, 5*time.Second, 50*time.Millisecond, "an expired lock was never taken over; a node that "+
		"crashed mid-issuance would block issuance for that domain forever")
}

// TestReleaseDoesNotRevokeALaterHolder is the fencing-token case. The holder's claim
// expires, another node takes over, and only then does the original release arrive - which
// must be a no-op. Without the token the stale release deletes the new holder's row and a
// third node acquires immediately, so two nodes run the guarded work at once: precisely
// the failure the lock exists to prevent.
func TestReleaseDoesNotRevokeALaterHolder(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	ctx := context.Background()
	database := setupTestDatabase(t)
	defer database.Close()

	name := fmt.Sprintf("test-lock-fencing-%d", time.Now().UnixNano())

	stale, err := database.TryAcquireNamedLock(ctx, name, time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, stale)

	var current *NamedLock
	require.Eventually(t, func() bool {
		current, err = database.TryAcquireNamedLock(ctx, name, time.Minute)
		return err == nil && current != nil
	}, 5*time.Second, 50*time.Millisecond)

	// The original holder finishes its work and releases, unaware it was superseded.
	require.NoError(t, database.ReleaseNamedLock(ctx, stale))

	// The new holder's claim must survive it.
	intruder, err := database.TryAcquireNamedLock(ctx, name, time.Minute)
	require.NoError(t, err)
	require.Nil(t, intruder, "a superseded holder's release freed the current holder's lock, "+
		"letting a third node in while the second is still working")

	require.NoError(t, database.ReleaseNamedLock(ctx, current))
}

// TestNamedLockExtensionOutlivesItsTTL covers work that runs longer than the lock was
// taken for. An extended lock must not be taken over at its original expiry, and must
// still be released by the token it was granted with.
func TestNamedLockExtensionOutlivesItsTTL(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	ctx := context.Background()
	database := setupTestDatabase(t)
	defer database.Close()

	name := fmt.Sprintf("test-lock-extend-%d", time.Now().UnixNano())

	lock, err := database.TryAcquireNamedLock(ctx, name, time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, lock)

	// Past its expiry but never taken over, the lock is still the holder's.
	time.Sleep(10 * time.Millisecond)
	extended, err := database.ExtendNamedLock(ctx, lock, time.Minute)
	require.NoError(t, err)
	require.True(t, extended, "a lock nobody took over could not be extended by its holder")

	intruder, err := database.TryAcquireNamedLock(ctx, name, time.Minute)
	require.NoError(t, err)
	require.Nil(t, intruder, "an extended lock was taken over at its original expiry: a second "+
		"node starts the work while the holder is still doing it")

	// A shorter extension does not shorten it.
	extended, err = database.ExtendNamedLock(ctx, lock, time.Millisecond)
	require.NoError(t, err)
	require.True(t, extended)
	time.Sleep(10 * time.Millisecond)
	intruder, err = database.TryAcquireNamedLock(ctx, name, time.Minute)
	require.NoError(t, err)
	require.Nil(t, intruder, "a shorter extension cut the lock short")

	require.NoError(t, database.ReleaseNamedLock(ctx, lock))
	next, err := database.TryAcquireNamedLock(ctx, name, time.Minute)
	require.NoError(t, err)
	require.NotNil(t, next, "an extended lock was not released by its own token")
	require.NoError(t, database.ReleaseNamedLock(ctx, next))
}

// TestExtendDoesNotReviveASupersededLock is the fencing-token case for extensions: a
// holder whose lock expired and was taken over must learn that it lost it, and must not
// move the new holder's expiry.
func TestExtendDoesNotReviveASupersededLock(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration test in short mode")
	}

	ctx := context.Background()
	database := setupTestDatabase(t)
	defer database.Close()

	name := fmt.Sprintf("test-lock-extend-fencing-%d", time.Now().UnixNano())

	stale, err := database.TryAcquireNamedLock(ctx, name, time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, stale)

	var current *NamedLock
	require.Eventually(t, func() bool {
		current, err = database.TryAcquireNamedLock(ctx, name, time.Millisecond)
		return err == nil && current != nil
	}, 5*time.Second, 50*time.Millisecond)

	extended, err := database.ExtendNamedLock(ctx, stale, time.Hour)
	require.NoError(t, err)
	require.False(t, extended, "a superseded holder extended the lock another node now holds")

	// The current holder's lock still expires when it was going to.
	require.Eventually(t, func() bool {
		taken, err := database.TryAcquireNamedLock(ctx, name, time.Minute)
		if err != nil || taken == nil {
			return false
		}
		require.NoError(t, database.ReleaseNamedLock(ctx, taken))
		return true
	}, 5*time.Second, 50*time.Millisecond, "a superseded holder's extension kept the current "+
		"holder's lock from expiring")

	// Nor can a lock whose row has since been taken over and released.
	extended, err = database.ExtendNamedLock(ctx, current, time.Minute)
	require.NoError(t, err)
	require.False(t, extended, "a lock that was taken over was extended by its former holder")
}
