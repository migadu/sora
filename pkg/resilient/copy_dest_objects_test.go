//go:build integration

package resilient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
)

// COPY uses its one write connection for the locks, S3 phase and rows. A single
// request can outlast both the write budget and PostgreSQL's idle transaction
// timeout, without holding an xid/xmin or granting the cleaner the object.
func TestCopyDestObjectsUseOneConnectionAcrossSlowS3(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cfg := testDatabaseConfig()
	cfg.WriteTimeout = "500ms"
	plain := newTestPool(t, cfg, nil)
	f := newCrossAccountMoveFixture(t, plain, 3)
	oneConfig := plain.Config()
	oneConfig.MaxConns = 1
	oneConfig.MinConns = 0
	oneConfig.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "600ms"
	one, err := pgxpool.NewWithConfig(ctx, oneConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(one.Close)
	rdb := newTestResilientDatabase(cfg, one)
	saved := destObjectKeepalive
	destObjectKeepalive = 50 * time.Millisecond
	t.Cleanup(func() { destObjectKeepalive = saved })

	ensured := f.hashes[:2]
	calls := 0
	ensure := func(work context.Context, hash string) error {
		calls++
		if n := one.Stat().AcquiredConns(); n != 1 {
			t.Errorf("COPY holds %d pooled connections during S3, want 1", n)
		}
		if cleanerCanLock(t, plain, f.ownerID, hash) {
			t.Error("cleaner could lock the destination during COPY's S3 check")
		}
		id := uint64(db.GetS3ObjectLockID(f.ownerID, hash))
		var xid, xmin *string
		if err := plain.QueryRow(work, `
			SELECT a.backend_xid::text, a.backend_xmin::text
			FROM pg_stat_activity a JOIN pg_locks l ON l.pid = a.pid
			WHERE l.locktype = 'advisory' AND l.mode = 'ShareLock' AND l.granted
			  AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database())
			  AND l.classid = $1::bigint::oid AND l.objid = $2::bigint::oid AND l.objsubid = 1`,
			int64(id>>32), int64(id&0xffffffff)).Scan(&xid, &xmin); err != nil {
			t.Errorf("find COPY's lock transaction: %v", err)
		} else if xid != nil || xmin != nil {
			t.Errorf("COPY holds xid=%v xmin=%v during S3", xid, xmin)
		}
		if calls == 1 {
			select {
			case <-time.After(1300 * time.Millisecond):
			case <-work.Done():
				return work.Err()
			}
		}
		return nil
	}
	uids := []imap.UID{1, 2, 3}
	sourceHashes := map[imap.UID]string{1: f.hashes[0], 2: f.hashes[1], 3: f.hashes[2]}
	uidMap, ids, err := rdb.CopyMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID,
		"example.net", "owner", "test-instance", sourceHashes, ensured, ensure)
	if err != nil {
		t.Fatalf("single-connection COPY with slow S3: %v", err)
	}
	if len(uidMap) != 3 || len(ids) != 3 || calls != 2 {
		t.Fatalf("COPY returned %d UIDs/%d IDs and made %d S3 checks", len(uidMap), len(ids), calls)
	}
	for i, hash := range f.hashes {
		var uploaded bool
		var pending int
		if err := plain.QueryRow(ctx, `SELECT uploaded FROM messages WHERE mailbox_id=$1 AND uid=$2`,
			f.destID, uidMap[imap.UID(i+1)]).Scan(&uploaded); err != nil {
			t.Fatal(err)
		}
		if err := plain.QueryRow(ctx, `SELECT count(*) FROM pending_uploads WHERE account_id=$1 AND content_hash=$2`,
			f.ownerID, hash).Scan(&pending); err != nil {
			t.Fatal(err)
		}
		if want := i < 2; uploaded != want {
			t.Errorf("body %d uploaded=%v, want %v: only ensured destination objects are uploaded", i+1, uploaded, want)
		}
		if want := map[bool]int{true: 0, false: 1}[i < 2]; pending != want {
			t.Errorf("body %d pending uploads=%d, want %d", i+1, pending, want)
		}
	}
	if countLiveMessages(t, plain, f.srcID) != 3 {
		t.Error("COPY removed source messages")
	}
	if !cleanerCanLock(t, plain, f.ownerID, ensured[0]) {
		t.Error("COPY's object lock survived its commit")
	}
}

func TestCopyDestObjectFailureIsNotADatabaseFailure(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	f := newCrossAccountMoveFixture(t, plain, 1)
	rdb := newTestResilientDatabase(cfg, plain)
	settings := circuitbreaker.DefaultSettings("test_copy_write")
	settings.IsSuccessful = isBreakerSuccess
	rdb.writeBreaker = circuitbreaker.NewCircuitBreaker(settings)
	calls := 0
	uids := []imap.UID{1}
	_, _, err := rdb.CopyMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID,
		"example.net", "owner", "test-instance", map[imap.UID]string{1: f.hashes[0]}, f.hashes,
		func(context.Context, string) error { calls++; return s3TimeoutError{} })
	var destErr *DestObjectError
	if !errors.As(err, &destErr) || !errors.Is(destErr.Err, s3TimeoutError{}) || isDatabaseFailure(err) {
		t.Fatalf("S3 timeout classification = %v", err)
	}
	if calls != 1 || rdb.writeBreaker.Counts().TotalFailures != 0 {
		t.Fatalf("S3 failure made %d calls and %d database failures", calls, rdb.writeBreaker.Counts().TotalFailures)
	}
	if countLiveMessages(t, plain, f.srcID) != 1 || countLiveMessages(t, plain, f.destID) != 0 {
		t.Fatal("failed COPY changed message rows")
	}
	if !cleanerCanLock(t, plain, f.ownerID, f.hashes[0]) {
		t.Error("failed COPY retained its object lock")
	}
}

func TestCopyCallerDeadlineDoesNotTripDatabaseBreaker(t *testing.T) {
	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	f := newCrossAccountMoveFixture(t, plain, 1)
	rdb := newTestResilientDatabase(cfg, plain)
	settings := circuitbreaker.DefaultSettings("test_copy_write")
	settings.IsSuccessful = isBreakerSuccess
	rdb.writeBreaker = circuitbreaker.NewCircuitBreaker(settings)
	saved := destObjectKeepalive
	destObjectKeepalive = 25 * time.Millisecond
	defer func() { destObjectKeepalive = saved }()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	uids := []imap.UID{1}
	_, _, err := rdb.CopyMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID,
		"example.net", "owner", "test-instance", map[imap.UID]string{1: f.hashes[0]}, f.hashes,
		func(work context.Context, _ string) error { <-work.Done(); return work.Err() })
	if err == nil {
		t.Fatal("caller deadline did not fail COPY")
	}
	if failures := rdb.writeBreaker.Counts().TotalFailures; failures != 0 {
		t.Fatalf("caller deadline counted as %d database failures", failures)
	}
	if countLiveMessages(t, plain, f.srcID) != 1 || countLiveMessages(t, plain, f.destID) != 0 {
		t.Fatal("caller cancellation changed message rows")
	}
	if !cleanerCanLock(t, plain, f.ownerID, f.hashes[0]) {
		t.Error("canceled COPY retained its object lock")
	}
}
