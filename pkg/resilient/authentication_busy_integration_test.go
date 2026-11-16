//go:build integration

package resilient

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/migadu/sora/authcache"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/server/credchanges"
	"golang.org/x/crypto/bcrypt"
)

func TestAuthRevocationRetriesSQLiteBusyWithoutLosingChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, primary := authFenceDatabase(t, "busy")
	const address = "busy-revocation@example.com"
	oldHash, newHash := authFenceHash(t, "old-test-password"), authFenceHash(t, "new-test-password")
	id := authFenceCredential(t, primary, address, oldHash)
	rd := newTestResilientDatabase(cfg, primary)
	path := filepath.Join(t.TempDir(), "auth.db")
	persistent, err := authcache.New(path, time.Hour, 24*time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { persistent.Close() })
	cache := &observedAuthFill{Cache: persistent, filled: make(chan struct{})}
	rd.SetAuthCache(cache)
	var requested, boundaries []int64
	var accounts [][]int64
	load := func(ctx context.Context, cursor int64) (db.CredentialChanges, error) {
		requested = append(requested, cursor)
		changes, err := rd.GetCredentialChangesSinceWithRetry(ctx, cursor)
		boundaries = append(boundaries, changes.NextCursor)
		accounts = append(accounts, slices.Clone(changes.Accounts))
		return changes, err
	}
	watcher := credchanges.New(load, rd.PruneCredentialChangesWithRetry, credchanges.Sinks{
		AuthCache: cache, Suspend: cache.Suspend,
		Synchronized: cache.Resume, Reset: cache.InvalidateAll,
	}, time.Hour)
	identity, err := rd.GetDatabaseIdentityWithRetry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.EnsureRevocationNamespace(ctx, identity); err != nil {
		t.Fatal(err)
	}
	if err := watcher.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := persistent.Put(ctx, address, id, oldHash); err != nil {
		t.Fatal(err)
	}
	if _, err := primary.Exec(ctx, `UPDATE credentials SET password=$1 WHERE account_id=$2`, newHash, id); err != nil {
		t.Fatal(err)
	}
	// Age the diagnostic timestamp beyond the former one-minute overlap. This
	// models that state directly; it does not claim two minutes of elapsed time.
	if _, err := primary.Exec(ctx, `UPDATE credential_changes
		SET changed_at=clock_timestamp()-interval '2 minutes' WHERE account_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	blocker, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	writer, err := blocker.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	defer writer.ExecContext(context.Background(), `ROLLBACK`)
	failedCtx, failedCancel := context.WithTimeout(ctx, 100*time.Millisecond)
	err = watcher.Refresh(failedCtx)
	failedCancel()
	if err == nil {
		t.Fatal("revocation DELETE should fail while the real SQLite writer lock is held")
	}
	if len(requested) != 2 || !slices.Contains(accounts[1], id) {
		t.Fatal("failed application did not actually read the committed credential change")
	}
	var persistedHash string
	if err := writer.QueryRowContext(ctx, `SELECT password_hash FROM auth_cache WHERE address=?`, address).Scan(&persistedHash); err != nil || persistedHash != oldHash {
		t.Fatalf("busy fixture did not leave the revoked SQLite row present: err=%v", err)
	}
	failedCursor := requested[1]
	if failedCursor != boundaries[0] {
		t.Fatal("initial successful feed checkpoint was not used")
	}
	if _, _, err := cache.Get(ctx, address); !errors.Is(err, authcache.ErrCacheMiss) {
		t.Fatalf("failed invalidation still exposes the old SQLite row: %v", err)
	}
	// While SQLite is still locked, cache reads/fills stay disabled and login
	// remains available through the primary, which already has the new password.
	if _, err := rd.AuthenticateWithRetry(ctx, address, "old-test-password"); !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		t.Fatalf("old password accepted during cache quarantine: %v", err)
	}
	if got, err := rd.AuthenticateWithRetry(ctx, address, "new-test-password"); err != nil || got != id {
		t.Fatalf("new primary password unavailable during SQLite busy: id=%d err=%v", got, err)
	}
	select {
	case <-cache.filled:
	case <-ctx.Done():
		t.Fatal("quarantined asynchronous fill did not finish")
	}
	if _, err := writer.ExecContext(ctx, `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	if err := watcher.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if len(requested) != 3 || requested[2] != failedCursor || !slices.Contains(accounts[2], id) {
		t.Fatal("retry advanced past the failed checkpoint or lost the aged change")
	}
	t.Logf("failed input cursor=%d attempted boundary=%d retry input=%d", failedCursor, boundaries[1], requested[2])
	if _, _, err := cache.Get(ctx, address); !errors.Is(err, authcache.ErrCacheMiss) {
		t.Fatalf("successful recovery did not flush the previously failed cache state: %v", err)
	}
	if _, err := rd.AuthenticateWithRetry(ctx, address, "old-test-password"); !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		t.Fatalf("revoked password accepted after retry: %v", err)
	}
}
