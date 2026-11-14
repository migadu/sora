//go:build integration

package resilient

import (
	"context"
	"errors"
	"github.com/migadu/go-imap"
	"github.com/migadu/sora/db"
	"github.com/migadu/sora/pkg/circuitbreaker"
	"testing"
	"time"
)

func TestMoveSingleLongObjectKeepsTransactionAlive(t *testing.T) {
	ctx := context.Background()
	cfg := testDatabaseConfig()
	cfg.WriteTimeout = "5s"
	plain := newTestPool(t, cfg, nil)
	f := newCrossAccountMoveFixture(t, plain, 1)
	rdb := newTestResilientDatabase(cfg, newShortIdlePool(t, cfg, time.Second))
	saved := destObjectKeepalive
	destObjectKeepalive = 100 * time.Millisecond
	t.Cleanup(func() { destObjectKeepalive = saved })
	ensure := func(ctx context.Context, hash string) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1300 * time.Millisecond):
			return nil
		}
	}
	uids := []imap.UID{1}
	_, err := rdb.MoveMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID, "example.net", "owner", "test-instance", f.hashes, ensure)
	if err != nil {
		t.Fatalf("MOVE with a single slow S3 request: %v", err)
	}
}

func TestMoveKeepaliveLossCancelsObjectRequest(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	f := newCrossAccountMoveFixture(t, plain, 1)
	rdb := newTestResilientDatabase(cfg, plain)
	tx, err := plain.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var pid int
	if err := tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if err := db.LockS3ObjectsSharedInTx(ctx, tx, f.ownerID, f.hashes); err != nil {
		t.Fatal(err)
	}
	saved := destObjectKeepalive
	destObjectKeepalive = 50 * time.Millisecond
	defer func() { destObjectKeepalive = saved }()
	started := make(chan struct{})
	killed := make(chan error, 1)
	go func() {
		<-started
		_, err := plain.Exec(ctx, "SELECT pg_terminate_backend($1)", pid)
		killed <- err
	}()
	err = rdb.ensureDestObjects(ctx, tx, f.hashes, func(work context.Context, _ string) error {
		close(started)
		<-work.Done()
		return work.Err()
	})
	if killErr := <-killed; killErr != nil {
		t.Fatal(killErr)
	}
	var destErr *DestObjectError
	if err == nil || errors.As(err, &destErr) || !isDatabaseFailure(err) {
		t.Fatalf("lost transaction must cancel S3 and report the database failure, got %v", err)
	}
	if ctx.Err() != nil {
		t.Fatalf("keepalive failed to interrupt S3 before the caller deadline: %v", ctx.Err())
	}
}

func TestMoveCallerDeadlineDoesNotTripDatabaseBreaker(t *testing.T) {
	cfg := testDatabaseConfig()
	plain := newTestPool(t, cfg, nil)
	f := newCrossAccountMoveFixture(t, plain, 1)
	rdb := newTestResilientDatabase(cfg, plain)
	settings := circuitbreaker.DefaultSettings("test_write")
	settings.IsSuccessful = isBreakerSuccess
	rdb.writeBreaker = circuitbreaker.NewCircuitBreaker(settings)
	saved := destObjectKeepalive
	destObjectKeepalive = 25 * time.Millisecond
	defer func() { destObjectKeepalive = saved }()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	uids := []imap.UID{1}
	_, err := rdb.MoveMessagesWithRetry(ctx, &uids, f.srcID, f.destID, f.ownerID, "example.net", "owner", "test-instance", f.hashes, func(work context.Context, _ string) error {
		<-work.Done()
		return work.Err()
	})
	if err == nil {
		t.Fatal("caller deadline must fail the MOVE")
	}
	if failures := rdb.writeBreaker.Counts().TotalFailures; failures != 0 {
		t.Fatalf("caller deadline counted as %d database failures", failures)
	}
	if countLiveMessages(t, plain, f.srcID) != 1 || countLiveMessages(t, plain, f.destID) != 0 {
		t.Fatal("caller deadline must leave the message in the source only")
	}
}
