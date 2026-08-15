package db

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestLockMailboxMetricCardinalityIsBounded ensures LockMailbox does not add a
// metric series per mailbox: every series created here is retained by the
// process registry for its entire lifetime.
func TestLockMailboxMetricCardinalityIsBounded(t *testing.T) {
	db := &Database{}

	// Deltas, not absolutes: the histogram is a package global shared with the
	// other tests in this binary.
	before := testutil.CollectAndCount(mailboxLockWaitDuration)

	const mailboxes = 1000
	for id := int64(1); id <= mailboxes; id++ {
		unlock := db.LockMailbox(id)
		unlock()
	}

	after := testutil.CollectAndCount(mailboxLockWaitDuration)
	if delta := after - before; delta > 1 {
		t.Fatalf("LockMailbox over %d mailboxes added %d metric series (before=%d, after=%d); series count must not scale with the number of mailboxes",
			mailboxes, delta, before, after)
	}
}

// TestLockMailboxStripesAreReused ensures the mutex table has a fixed size:
// mailbox IDs one full stripe span apart must share a mutex.
func TestLockMailboxStripesAreReused(t *testing.T) {
	db := &Database{}

	if a, b := db.mailboxMutex(7), db.mailboxMutex(7+mailboxLockStripes); a != b {
		t.Fatalf("mailbox IDs %d and %d map to different mutexes (%p, %p); the mutex table is not bounded",
			7, 7+mailboxLockStripes, a, b)
	}
}

// TestLockMailboxSerializesSameMailbox ensures striping did not weaken the
// per-mailbox exclusion the lock exists for.
func TestLockMailboxSerializesSameMailbox(t *testing.T) {
	db := &Database{}

	const goroutines = 8
	const increments = 500

	var wg sync.WaitGroup
	counter := 0
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < increments; j++ {
				unlock := db.LockMailbox(42)
				counter++
				unlock()
			}
		}()
	}
	wg.Wait()

	if counter != goroutines*increments {
		t.Fatalf("counter = %d, want %d: LockMailbox did not serialize access to the same mailbox", counter, goroutines*increments)
	}
}
