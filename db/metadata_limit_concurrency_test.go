package db

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// setMetadataWhileAnotherIsOpen runs first in a transaction it keeps open, then
// second in another transaction, waits until second has either returned or is
// waiting for a lock, commits first, and commits second if it succeeded. It
// returns second's error: what a SETMETADATA gets while another SETMETADATA of
// the account is still in flight.
func setMetadataWhileAnotherIsOpen(t *testing.T, db *Database, first, second func(context.Context, pgx.Tx) error) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	txA, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	defer txA.Rollback(context.Background())
	require.NoError(t, first(ctx, txA), "the first write is within the limits")

	pidCh := make(chan uint32, 1)
	errCh := make(chan error, 1)
	go func() {
		txB, err := db.GetWritePool().Begin(ctx)
		if err != nil {
			errCh <- err
			return
		}
		defer txB.Rollback(context.Background())
		var pid uint32
		if err := txB.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
			errCh <- err
			return
		}
		pidCh <- pid
		if err := second(ctx, txB); err != nil {
			errCh <- err
			return
		}
		errCh <- txB.Commit(ctx)
	}()

	var pid uint32
	select {
	case pid = <-pidCh:
	case err := <-errCh:
		t.Fatalf("second transaction failed to start: %v", err)
	}

	// The second write either finishes without waiting for the first (the race)
	// or waits for a lock until the first commits.
	var secondErr error
	secondDone := false
	for !secondDone {
		select {
		case secondErr = <-errCh:
			secondDone = true
		case <-time.After(20 * time.Millisecond):
			var waitType *string
			require.NoError(t, db.GetWritePool().QueryRow(ctx,
				"SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1", pid).Scan(&waitType))
			if waitType != nil && *waitType == "Lock" {
				require.NoError(t, txA.Commit(ctx))
				select {
				case secondErr = <-errCh:
				case <-ctx.Done():
					t.Fatalf("second write still waiting after the first committed")
				}
				return secondErr
			}
		case <-ctx.Done():
			t.Fatalf("second write neither finished nor waited for a lock")
		}
	}
	require.NoError(t, txA.Commit(ctx))
	return secondErr
}

func requireMetadataErrorType(t *testing.T, err error, want MetadataErrorType) {
	t.Helper()
	var metaErr *MetadataError
	if !errors.As(err, &metaErr) {
		t.Fatalf("expected a MetadataError of type %d, got %T: %v", want, err, err)
	}
	require.Equal(t, want, metaErr.Type, "MetadataError type (%v)", err)
}

// TestMetadataCountLimitHoldsWhileAnotherSetIsOpen: the entry count limit must
// hold when two SETMETADATA commands of one account run at the same time. The
// count was read and compared without anything serialising the account, so a
// second write that started before the first committed saw the old count, passed,
// and both entries were stored.
func TestMetadataCountLimitHoldsWhileAnotherSetIsOpen(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()
	accountID := createTestAccount(t, db, fmt.Sprintf("test-meta-race-count-%d@example.com", time.Now().UnixNano()), "password")
	limits := &MetadataLimits{MaxEntriesPerServer: 2}

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.SetMetadata(ctx, tx, accountID, nil, map[string]*[]byte{"/private/k0": bytePtr([]byte("v"))}, limits))
	require.NoError(t, tx.Commit(ctx))

	secondErr := setMetadataWhileAnotherIsOpen(t, db,
		func(ctx context.Context, tx pgx.Tx) error {
			return db.SetMetadata(ctx, tx, accountID, nil, map[string]*[]byte{"/private/k1": bytePtr([]byte("v"))}, limits)
		},
		func(ctx context.Context, tx pgx.Tx) error {
			return db.SetMetadata(ctx, tx, accountID, nil, map[string]*[]byte{"/private/k2": bytePtr([]byte("v"))}, limits)
		})

	var stored int
	require.NoError(t, db.GetWritePool().QueryRow(ctx,
		"SELECT COUNT(*) FROM metadata WHERE account_id = $1 AND mailbox_id IS NULL", accountID).Scan(&stored))
	require.LessOrEqual(t, stored, limits.MaxEntriesPerServer, "server entries stored past max_entries_per_server")
	requireMetadataErrorType(t, secondErr, MetadataErrTooMany)
}

// TestMetadataTotalSizeHoldsWhileAnotherSetIsOpen: the account's total size limit
// covers server and mailbox entries together, so a server-scope write and a
// mailbox-scope write of one account running at the same time must not both pass.
func TestMetadataTotalSizeHoldsWhileAnotherSetIsOpen(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	db := setupTestDatabase(t)
	ctx := context.Background()
	accountID := createTestAccount(t, db, fmt.Sprintf("test-meta-race-size-%d@example.com", time.Now().UnixNano()), "password")
	limits := &MetadataLimits{MaxTotalSize: 10}

	tx, err := db.GetWritePool().Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, db.CreateMailbox(ctx, tx, accountID, "RaceBox", nil))
	require.NoError(t, tx.Commit(ctx))
	mailbox, err := db.GetMailboxByName(ctx, accountID, "RaceBox")
	require.NoError(t, err)
	mailboxID := mailbox.ID

	secondErr := setMetadataWhileAnotherIsOpen(t, db,
		func(ctx context.Context, tx pgx.Tx) error {
			return db.SetMetadata(ctx, tx, accountID, nil, map[string]*[]byte{"/private/a": bytePtr([]byte("123456"))}, limits)
		},
		func(ctx context.Context, tx pgx.Tx) error {
			return db.SetMetadata(ctx, tx, accountID, &mailboxID, map[string]*[]byte{"/private/b": bytePtr([]byte("123456"))}, limits)
		})

	var total int
	require.NoError(t, db.GetWritePool().QueryRow(ctx,
		"SELECT COALESCE(SUM(LENGTH(entry_value)), 0) FROM metadata WHERE account_id = $1", accountID).Scan(&total))
	require.LessOrEqual(t, total, limits.MaxTotalSize, "metadata stored past max_total_size")
	requireMetadataErrorType(t, secondErr, MetadataErrQuotaExceeded)
}

// TestMetadataCountLimitHoldsUnderConcurrentSets is the issue's reproduction:
// many SETMETADATA commands of one account, each adding a different entry, at the
// same time. No more than the limit may succeed or be stored.
func TestMetadataCountLimitHoldsUnderConcurrentSets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database integration test")
	}

	const writers = 20
	// A connection per writer, so every transaction is open before any of them
	// writes.
	db := setupTestDatabaseWithMaxConns(t, writers+2)
	defer db.Close()
	ctx := context.Background()
	accountID := createTestAccount(t, db, fmt.Sprintf("test-meta-race-burst-%d@example.com", time.Now().UnixNano()), "password")
	limits := &MetadataLimits{MaxEntriesPerServer: 5}

	start := make(chan struct{})
	errs := make([]error, writers)
	var ready, wg sync.WaitGroup
	for i := range writers {
		ready.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := db.GetWritePool().Begin(ctx)
			ready.Done()
			if err != nil {
				errs[i] = err
				return
			}
			defer tx.Rollback(context.Background())
			<-start
			if err := db.SetMetadata(ctx, tx, accountID, nil,
				map[string]*[]byte{fmt.Sprintf("/private/k%d", i): bytePtr([]byte("v"))}, limits); err != nil {
				errs[i] = err
				return
			}
			errs[i] = tx.Commit(ctx)
		}()
	}
	ready.Wait()
	close(start)
	wg.Wait()

	accepted := 0
	for i, err := range errs {
		if err == nil {
			accepted++
			continue
		}
		var metaErr *MetadataError
		if !errors.As(err, &metaErr) || metaErr.Type != MetadataErrTooMany {
			t.Fatalf("writer %d: expected success or MetadataErrTooMany, got %T: %v", i, err, err)
		}
	}
	var stored int
	require.NoError(t, db.GetWritePool().QueryRow(ctx,
		"SELECT COUNT(*) FROM metadata WHERE account_id = $1 AND mailbox_id IS NULL", accountID).Scan(&stored))
	require.Equal(t, limits.MaxEntriesPerServer, accepted, "SETMETADATA commands accepted")
	require.Equal(t, limits.MaxEntriesPerServer, stored, "server entries stored")
}
