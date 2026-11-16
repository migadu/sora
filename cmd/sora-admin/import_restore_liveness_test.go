//go:build integration

package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/testutils"
	"github.com/stretchr/testify/require"
)

type pausedImportPut struct {
	*testutils.FileBasedS3Mock
	entered, release chan struct{}
	once             sync.Once
}

func (s *pausedImportPut) Put(key string, r io.Reader, size int64) error {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return s.FileBasedS3Mock.Put(key, r, size)
}

func TestImportAndRestoreSameBodyDoNotWaitOnEachOther(t *testing.T) {
	f := newRekeyFixture(t)
	account, domain, local := f.account("restore-overlap")
	body := f.body("restore-overlap")
	candidate := expungedCandidate(f, account, domain, local, body)
	var oldID int64
	require.NoError(t, f.rdb.QueryRowWithRetry(f.ctx, `SELECT id FROM messages WHERE account_id=$1 AND content_hash=$2`, account, candidate.ContentHash).Scan(&oldID))
	maildir := filepath.Join(t.TempDir(), "Maildir")
	for _, n := range []string{"cur", "new", "tmp"} {
		require.NoError(t, os.MkdirAll(filepath.Join(maildir, n), 0700))
	}
	require.NoError(t, os.WriteFile(filepath.Join(maildir, "cur", "1700000001.M1P1.host:2,S"), body, 0600))
	store := &pausedImportPut{FileBasedS3Mock: f.store, entered: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	releasePut := func() { releaseOnce.Do(func() { close(store.release) }) }
	defer releasePut()
	importCtx, stopImport := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopImport()
	importer, err := NewImporter(importCtx, maildir, local+"@"+domain, 1, f.rdb, store, ImporterOptions{})
	require.NoError(t, err)
	defer importer.Close()
	imported := make(chan error, 1)
	go func() { imported <- importer.Run() }()
	select {
	case <-store.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("import did not hold its body claim before PUT")
	}
	restoreCtx, stopRestore := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopRestore()
	pool := f.rdb.GetOperationalDatabase().GetWritePool()
	tx, err := pool.Begin(restoreCtx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	var pid int
	require.NoError(t, tx.QueryRow(restoreCtx, `SELECT pg_backend_pid()`).Scan(&pid))
	restored := make(chan error, 1)
	go func() {
		_, e := f.rdb.GetOperationalDatabase().RestoreMessages(restoreCtx, tx, db.RestoreMessagesParams{Email: local + "@" + domain, MessageIDs: []int64{oldID}})
		if e == nil {
			e = tx.Commit(restoreCtx)
		}
		restored <- e
	}()
	var restoreErr error
	restoreDone := false
	exclusiveWait := false
	deadline := time.After(time.Second)
waitRestore:
	for {
		select {
		case restoreErr = <-restored:
			restoreDone = true
			break waitRestore
		case <-deadline:
			t.Fatal("restore neither finished nor reached its body-lock wait")
		default:
		}
		require.NoError(t, pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted AND mode='ExclusiveLock')`, pid).Scan(&exclusiveWait))
		if exclusiveWait {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Logf("restorePID=%d finished_while_outer_shared=%v waiting_exclusive=%v", pid, restoreDone, exclusiveWait)
	releasePut()
	var importErr error
	select {
	case importErr = <-imported:
	case <-time.After(7 * time.Second):
		stopImport()
		t.Fatal("import failed to stop at its bounded context")
	}
	if !restoreDone {
		select {
		case restoreErr = <-restored:
		case <-time.After(7 * time.Second):
			stopRestore()
			t.Fatal("restore failed to finish after import released its holder")
		}
	}
	require.NoError(t, importErr, "a compatible restore forced the live import to wait until its deadline")
	require.NoError(t, restoreErr)
}
