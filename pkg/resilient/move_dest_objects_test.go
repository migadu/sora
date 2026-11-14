//go:build integration

package resilient

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
)

// crossAccountMoveFixture is a copyFixture whose DEST mailbox belongs to another
// account, so a move from SRC into DEST re-keys every row to that owner.
type crossAccountMoveFixture struct {
	copyFixture
	ownerID int64
	hashes  []string // content hash of SRC's message i+1
}

func newCrossAccountMoveFixture(t *testing.T, pool *pgxpool.Pool, messages int) crossAccountMoveFixture {
	t.Helper()
	ctx := context.Background()
	f := crossAccountMoveFixture{copyFixture: newCopyFixture(t, pool, messages)}
	if err := pool.QueryRow(ctx, `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&f.ownerID); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	// Runs before newCopyFixture's cleanup, which only knows the source account.
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		pool.Exec(cleanupCtx, `DELETE FROM pending_uploads WHERE account_id = $1`, f.ownerID)
		pool.Exec(cleanupCtx, `DELETE FROM messages WHERE account_id = $1`, f.ownerID)
		pool.Exec(cleanupCtx, `DELETE FROM mailboxes WHERE account_id = $1`, f.ownerID)
		pool.Exec(cleanupCtx, `DELETE FROM accounts WHERE id = $1`, f.ownerID)
	})
	if _, err := pool.Exec(ctx, `UPDATE mailboxes SET account_id = $1 WHERE id = $2`, f.ownerID, f.destID); err != nil {
		t.Fatalf("give DEST to the owner: %v", err)
	}
	for i := 1; i <= messages; i++ {
		f.hashes = append(f.hashes, fmt.Sprintf("hash-%d-%d", f.accountID, i))
	}
	return f
}

// newShortIdlePool is a pool on the test database whose sessions the server kills after
// idling in a transaction for idle.
func newShortIdlePool(t *testing.T, cfg *config.DatabaseConfig, idle time.Duration) *pgxpool.Pool {
	t.Helper()
	w := cfg.Write
	poolCfg, err := pgxpool.ParseConfig(fmt.Sprintf("postgres://%s@%s:%s/%s?sslmode=disable", w.User, w.Hosts[0], w.Port, w.Name))
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	poolCfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = fmt.Sprint(idle.Milliseconds())
	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// cleanerCanLock reports whether an exclusive try-lock of the object, which the
// cleaner takes before it deletes it, would be granted now.
func cleanerCanLock(t *testing.T, pool *pgxpool.Pool, accountID int64, hash string) bool {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)
	var granted bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, db.GetS3ObjectLockID(accountID, hash)).Scan(&granted); err != nil {
		t.Fatalf("try-lock: %v", err)
	}
	return granted
}

// TestMoveMessagesHoldsDestObjectsAcrossTheirCheck runs a cross-account move whose S3
// phase outlasts both the write timeout and the server's idle-in-transaction timeout.
// While each destination object is checked, the move's transaction must hold its lock
// (the cleaner's try-lock is refused) without a transaction id or snapshot; it must stay
// alive and give the writes their own budget; and the moved rows must be uploaded for
// exactly the bodies the S3 phase made exist under the owner's key.
func TestMoveMessagesHoldsDestObjectsAcrossTheirCheck(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	cfg.WriteTimeout = "1s"
	plain := newTestPool(t, cfg, nil)
	f := newCrossAccountMoveFixture(t, plain, 3)
	rdb := newTestResilientDatabase(cfg, newShortIdlePool(t, cfg, time.Second))

	saved := destObjectKeepalive
	destObjectKeepalive = 200 * time.Millisecond
	t.Cleanup(func() { destObjectKeepalive = saved })

	// Bodies 1 and 2 are in S3 and get their object under the owner's key; body 3 was
	// still staged when the caller looked, so it is not among them.
	held := f.hashes[:2]
	var ensured []string
	ensure := func(ctx context.Context, hash string) error {
		ensured = append(ensured, hash)
		if cleanerCanLock(t, plain, f.ownerID, hash) {
			t.Errorf("the cleaner could lock %s while the move checked it", hash)
		}
		var xid, xmin *string
		if err := plain.QueryRow(ctx, `
			SELECT a.backend_xid::text, a.backend_xmin::text
			FROM pg_stat_activity a
			JOIN pg_locks l ON l.pid = a.pid
			WHERE l.locktype = 'advisory' AND l.mode = 'ShareLock' AND l.granted
			  AND l.classid = $1::bigint::oid AND l.objid = $2::bigint::oid AND l.objsubid = 1`,
			int64(uint64(db.GetS3ObjectLockID(f.ownerID, hash))>>32),
			int64(uint64(db.GetS3ObjectLockID(f.ownerID, hash))&0xffffffff)).Scan(&xid, &xmin); err != nil {
			t.Errorf("find the move's backend: %v", err)
		} else if xid != nil || xmin != nil {
			t.Errorf("the move's transaction holds xid=%v xmin=%v across the S3 phase", xid, xmin)
		}
		time.Sleep(700 * time.Millisecond) // the two calls together outlast both timeouts
		return nil
	}

	uids := []imap.UID{1, 2, 3}
	uidMap, err := rdb.MoveMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID, "example.net", "owner", "test-instance", held, ensure)
	if err != nil {
		t.Fatalf("move: %v", err)
	}
	if len(uidMap) != 3 || len(ensured) != 2 {
		t.Fatalf("moved %d messages and ensured %v, want 3 and %v", len(uidMap), ensured, held)
	}
	for i, hash := range f.hashes {
		var uploaded bool
		var accountID int64
		var localpart string
		if err := plain.QueryRow(ctx, `SELECT uploaded, account_id, s3_localpart FROM messages WHERE mailbox_id = $1 AND uid = $2`,
			f.destID, uidMap[imap.UID(i+1)]).Scan(&uploaded, &accountID, &localpart); err != nil {
			t.Fatalf("read moved row %d: %v", i+1, err)
		}
		if accountID != f.ownerID || localpart != "owner" {
			t.Errorf("moved row %d is (%d, %s), want the owner's", i+1, accountID, localpart)
		}
		if want := i < 2; uploaded != want {
			t.Errorf("moved row %d (%s) uploaded = %v, want %v", i+1, hash, uploaded, want)
		}
		var pending int
		if err := plain.QueryRow(ctx, `SELECT count(*) FROM pending_uploads WHERE account_id = $1 AND content_hash = $2`,
			f.ownerID, hash).Scan(&pending); err != nil {
			t.Fatalf("count pending uploads: %v", err)
		}
		if want := map[bool]int{true: 0, false: 1}[i < 2]; pending != want {
			t.Errorf("moved row %d (%s) has %d pending uploads under the owner, want %d", i+1, hash, pending, want)
		}
	}
	if n := countLiveMessages(t, plain, f.srcID); n != 0 {
		t.Errorf("%d messages left in SRC", n)
	}
	if !cleanerCanLock(t, plain, f.ownerID, f.hashes[0]) {
		t.Error("the object lock outlived the move's commit")
	}
}

// s3TimeoutError is how a timed-out S3 call can surface: a net.Error.
type s3TimeoutError struct{}

func (s3TimeoutError) Error() string   { return "synthetic: S3 request timed out" }
func (s3TimeoutError) Timeout() bool   { return true }
func (s3TimeoutError) Temporary() bool { return true }

// TestMoveMessagesDestObjectFailureIsNotADatabaseFailure checks that an S3 failure in the
// move's S3 phase fails the move once, moves nothing, and is not taken for a database
// failure: it is neither retried nor counted against the write circuit breaker.
func TestMoveMessagesDestObjectFailureIsNotADatabaseFailure(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	f := newCrossAccountMoveFixture(t, plain, 1)
	rdb := newTestResilientDatabase(cfg, plain)
	settings := circuitbreaker.DefaultSettings("test_write")
	settings.IsSuccessful = isBreakerSuccess
	rdb.writeBreaker = circuitbreaker.NewCircuitBreaker(settings)

	var calls atomic.Int32
	ensure := func(context.Context, string) error {
		calls.Add(1)
		return s3TimeoutError{}
	}
	uids := []imap.UID{1}
	_, err := rdb.MoveMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID, "example.net", "owner", "test-instance", f.hashes, ensure)
	var destErr *DestObjectError
	if !errors.As(err, &destErr) || destErr.ContentHash != f.hashes[0] || !errors.Is(destErr.Err, s3TimeoutError{}) {
		t.Fatalf("move error = %v, want a DestObjectError carrying the S3 failure", err)
	}
	var netErr interface{ Timeout() bool }
	if errors.As(err, &netErr) || isDatabaseFailure(err) {
		t.Errorf("the S3 failure passes for a database failure: %v", err)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("the S3 phase ran %d times, want 1 (no retry)", n)
	}
	if failures := rdb.writeBreaker.Counts().TotalFailures; failures != 0 {
		t.Errorf("the write breaker counted %d failures for an S3 failure", failures)
	}
	if n := countLiveMessages(t, plain, f.srcID); n != 1 {
		t.Errorf("%d messages left in SRC, want 1", n)
	}
	if n := countLiveMessages(t, plain, f.destID); n != 0 {
		t.Errorf("%d messages in DEST, want 0", n)
	}
}
