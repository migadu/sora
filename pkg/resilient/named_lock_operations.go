package resilient

import (
	"context"
	"time"

	"github.com/migadu/sora/db"
)

// Named locks are deliberately NOT run inside a caller's transaction, unlike most
// operations in this package. A lock is only a fence if the other nodes can see it, and a
// row written inside an open transaction is invisible until that transaction commits - so
// joining a caller's transaction would let two nodes both believe they hold the lock for
// as long as their surrounding work took to commit.
//
// They are also not retried. A retry after an ambiguous failure could take a lock the
// caller then never learns about and never releases, holding it until the ttl expires.
// Treating an uncertain acquire as "not acquired" is the safe reading: the caller stands
// down, and the worst case is that nobody does the work this round.

// TryAcquireNamedLockWithRetry takes a named, expiring lock, returning nil if another
// node holds it. Despite the name it does not retry; see above.
func (rd *ResilientDatabase) TryAcquireNamedLockWithRetry(ctx context.Context, name string, ttl time.Duration) (*db.NamedLock, error) {
	return rd.getOperationalDatabaseForOperation(ctx, true).TryAcquireNamedLock(ctx, name, ttl)
}

// ReleaseNamedLockWithRetry hands a held lock back before its expiry.
func (rd *ResilientDatabase) ReleaseNamedLockWithRetry(ctx context.Context, lock *db.NamedLock) error {
	return rd.getOperationalDatabaseForOperation(ctx, true).ReleaseNamedLock(ctx, lock)
}
