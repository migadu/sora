//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/helpers"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// terminateSharedBodyLockHolder terminates the PostgreSQL backend holding the outer
// ShareLock advisory lock for (accountID, hash) and waits until the backend exits so
// subsequent holder checks deterministically observe the dropped session.
func terminateSharedBodyLockHolder(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64, hash string) int {
	t.Helper()
	ctx := context.Background()
	pool := rdb.GetOperationalDatabase().GetWritePool()
	lockID := uint64(db.GetS3ObjectLockID(accountID, hash))

	var outerPID int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT pid FROM pg_locks
		WHERE locktype = 'advisory'
		  AND granted
		  AND mode = 'ShareLock'
		  AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
		  AND classid = $1::bigint::oid
		  AND objid = $2::bigint::oid
		  AND objsubid = 1`,
		int64(lockID>>32), int64(lockID&0xffffffff),
	).Scan(&outerPID))

	var killed bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT pg_terminate_backend($1)`, outerPID).Scan(&killed))
	require.True(t, killed, "expected pg_terminate_backend to signal advisory-lock holder backend")

	require.Eventually(t, func() bool {
		var stillHolding bool
		err := pool.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM pg_locks
				WHERE pid = $1 AND locktype = 'advisory' AND granted
			)`, outerPID).Scan(&stillHolding)
		return err == nil && !stillHolding
	}, 5*time.Second, 5*time.Millisecond, "advisory-lock holder backend %d did not exit after pg_terminate_backend", outerPID)

	return outerPID
}

// observeTerminatedHolderOnGuard forces the AdvisoryLockTx carrying ctx's S3 body claim
// to ping its terminated connection immediately (instead of waiting 30s for keepalive)
// so lock.Guard(i.ctx) cancels right inside uploadBatchToS3 while i.ctx stays live.
func observeTerminatedHolderOnGuard(t *testing.T, ctx context.Context, rdb *resilient.ResilientDatabase, hash string) {
	t.Helper()
	pool := rdb.GetOperationalDatabase().GetWritePool()
	probeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx, err := pool.Begin(probeCtx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background())

	_ = db.CheckS3BodyClaims(ctx, tx, []string{hash})
	require.Error(t, ctx.Err(), "guarded batch context must be cancelled once AdvisoryLockTx observes holder termination")
}

// guardLossUploadStorage wraps FileBasedS3Mock and terminates the ShareLock holder
// backend on the configured 1-based PUT attempt.
type guardLossUploadStorage struct {
	*testutils.FileBasedS3Mock
	t                 *testing.T
	rdb               *resilient.ResilientDatabase
	accountID         int64
	terminateOnPutNum int32
	observeInUpload   bool
	cancelOperator    context.CancelFunc
	puts              atomic.Int32
}

func (s *guardLossUploadStorage) PutContext(ctx context.Context, key string, body io.Reader, size int64) error {
	n := s.puts.Add(1)
	if n == s.terminateOnPutNum {
		hash := filepath.Base(key)
		if s.cancelOperator != nil {
			s.cancelOperator()
			return ctx.Err()
		}
		terminateSharedBodyLockHolder(s.t, s.rdb, s.accountID, hash)
		if s.observeInUpload {
			observeTerminatedHolderOnGuard(s.t, ctx, s.rdb, hash)
			return ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.FileBasedS3Mock.Put(key, body, size)
}

// guardLossInsertDB delegates all calls to a real *resilient.ResilientDatabase and
// terminates the batch's outer ShareLock holder connection right after the configured
// commit count, while i.ctx remains active.
type guardLossInsertDB struct {
	*resilient.ResilientDatabase
	t                       *testing.T
	accountID               int64
	lockHash                string
	terminateAfterBatchNum  int32
	terminateAfterSingleNum int32
	cancelOperator          context.CancelFunc
	batchCalls              atomic.Int32
	singleCalls             atomic.Int32
}

func (d *guardLossInsertDB) InsertMessagesFromImporterBatchWithRetry(ctx context.Context, opts []*db.InsertMessageOptions) ([]int64, []int64, []string, error) {
	ids, uids, hashes, err := d.ResilientDatabase.InsertMessagesFromImporterBatchWithRetry(ctx, opts)
	if err == nil && d.terminateAfterBatchNum > 0 && d.batchCalls.Add(1) == d.terminateAfterBatchNum {
		if d.cancelOperator != nil {
			d.cancelOperator()
		} else {
			terminateSharedBodyLockHolder(d.t, d.ResilientDatabase, d.accountID, d.lockHash)
		}
	}
	return ids, uids, hashes, err
}

func (d *guardLossInsertDB) InsertMessageFromImporterWithRetry(ctx context.Context, opts *db.InsertMessageOptions) (int64, int64, error) {
	id, uid, err := d.ResilientDatabase.InsertMessageFromImporterWithRetry(ctx, opts)
	if err == nil && d.terminateAfterSingleNum > 0 && d.singleCalls.Add(1) == d.terminateAfterSingleNum {
		if d.cancelOperator != nil {
			d.cancelOperator()
		} else {
			terminateSharedBodyLockHolder(d.t, d.ResilientDatabase, d.accountID, d.lockHash)
		}
	}
	return id, uid, err
}

func newGuardLossMaildirMessage(k int, tag string) (string, []byte) {
	name := fmt.Sprintf("1700000%03d.M%dP1.host:2,S", k, k)
	content := []byte(fmt.Sprintf(
		"From: sender@example.com\r\nTo: user@example.com\r\nSubject: Guard Loss %s %d\r\nMessage-ID: <guard-loss-%s-%d@example.com>\r\n\r\nBody %s %d\r\n",
		tag, k, tag, k, tag, k,
	))
	return name, content
}

func countAccountLiveMessages(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64) int {
	t.Helper()
	var live int
	require.NoError(t, rdb.GetOperationalDatabase().GetWritePool().QueryRow(context.Background(),
		`SELECT COUNT(*) FROM messages WHERE account_id = $1 AND expunged_at IS NULL`, accountID).Scan(&live))
	return live
}

func TestImporterGuardLossDuringUpload(t *testing.T) {
	t.Run("zero uploaded messages fails run, prints summary, records all paths, and preserves cache", func(t *testing.T) {
		f := newRekeyFixture(t)
		accountID, domain, localpart := f.account("guard-upload-zero")

		maildir := newCleanupDBMaildir(t, 0)
		var expectedPaths []string
		for k := 1; k <= 3; k++ {
			name, body := newGuardLossMaildirMessage(k, "zero")
			p := filepath.Join(maildir, "cur", name)
			require.NoError(t, os.WriteFile(p, body, 0o644))
			expectedPaths = append(expectedPaths, p)
		}

		s3Store := &guardLossUploadStorage{
			FileBasedS3Mock:   f.store,
			t:                 t,
			rdb:               f.rdb,
			accountID:         accountID,
			terminateOnPutNum: 1,
			observeInUpload:   true,
		}

		importer, err := NewImporter(f.ctx, maildir, localpart+"@"+domain, 1, f.rdb, s3Store, ImporterOptions{
			CleanupDB: true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { importer.Close() })

		out, runErr := runCapturingStdout(t, importer.Run)
		require.NoError(t, f.ctx.Err(), "operator context must remain active")
		require.Error(t, runErr, "guard loss with 0 uploaded messages must never succeed")
		assert.Equal(t, "import completed with 3 failed messages", runErr.Error())

		assert.Equal(t, int64(3), importer.totalMessages)
		assert.Zero(t, importer.importedMessages)
		assert.Zero(t, importer.skippedMessages)
		assert.Equal(t, int64(3), importer.failedMessages)
		assert.ElementsMatch(t, expectedPaths, recordedFailedPaths(importer))

		assert.Contains(t, out, "Import Summary:")
		assert.Contains(t, out, "Failed:            3")
		assert.Contains(t, out, "Failed Messages (3):")

		require.FileExists(t, filepath.Join(maildir, "sora-maildir.db"),
			"--cleanup-db must preserve sora-maildir.db when advisory-lock loss drops the batch")
		imported, pending := uploadedCounts(t, maildir)
		assert.Equal(t, 0, imported)
		assert.Equal(t, 3, pending)
		assert.Equal(t, 0, countAccountLiveMessages(t, f.rdb, accountID))
	})

	for _, mode := range []struct {
		name  string
		batch bool
	}{
		{name: "individual mode", batch: false},
		{name: "batch transaction mode", batch: true},
	} {
		t.Run("partial upload before guard loss fails all N messages/"+mode.name, func(t *testing.T) {
			f := newRekeyFixture(t)
			tag := "partial-ind"
			if mode.batch {
				tag = "partial-batch"
			}
			accountID, domain, localpart := f.account("guard-upload-" + tag)

			maildir := newCleanupDBMaildir(t, 0)
			var expectedPaths []string
			for k := 1; k <= 3; k++ {
				name, body := newGuardLossMaildirMessage(k, tag)
				p := filepath.Join(maildir, "cur", name)
				require.NoError(t, os.WriteFile(p, body, 0o644))
				expectedPaths = append(expectedPaths, p)
			}

			// Message 1 finishes S3 PUT; message 2 loses the advisory-lock guard;
			// message 3 sees <-ctx.Done() before starting PUT. None of the 3 may be
			// inserted into PostgreSQL or omitted from failedMessages/failedPaths.
			s3Store := &guardLossUploadStorage{
				FileBasedS3Mock:   f.store,
				t:                 t,
				rdb:               f.rdb,
				accountID:         accountID,
				terminateOnPutNum: 2,
				observeInUpload:   true,
			}

			importer, err := NewImporter(f.ctx, maildir, localpart+"@"+domain, 1, f.rdb, s3Store, ImporterOptions{
				CleanupDB:            true,
				BatchTransactionMode: mode.batch,
			})
			require.NoError(t, err)
			t.Cleanup(func() { importer.Close() })

			out, runErr := runCapturingStdout(t, importer.Run)
			require.NoError(t, f.ctx.Err(), "operator context must remain active")
			require.Error(t, runErr)
			assert.Equal(t, "import completed with 3 failed messages", runErr.Error())

			assert.Equal(t, int64(3), importer.totalMessages)
			assert.Zero(t, importer.importedMessages)
			assert.Zero(t, importer.skippedMessages)
			assert.Equal(t, int64(3), importer.failedMessages)
			assert.ElementsMatch(t, expectedPaths, recordedFailedPaths(importer))

			assert.Contains(t, out, "Import Summary:")
			assert.Contains(t, out, "Failed:            3")
			assert.Contains(t, out, "Failed Messages (3):")

			require.FileExists(t, filepath.Join(maildir, "sora-maildir.db"))
			imported, pending := uploadedCounts(t, maildir)
			assert.Equal(t, 0, imported)
			assert.Equal(t, 3, pending)
			assert.Equal(t, 0, countAccountLiveMessages(t, f.rdb, accountID))
		})
	}
}

func TestImporterGuardLossDuringInsert(t *testing.T) {
	t.Run("individual mode mid-batch after message 1 commits credits imported message 1 and fails remaining", func(t *testing.T) {
		f := newRekeyFixture(t)
		accountID, domain, localpart := f.account("guard-insert-ind")

		maildir := newCleanupDBMaildir(t, 0)
		for _, sub := range []string{"cur", "new", "tmp"} {
			require.NoError(t, os.MkdirAll(filepath.Join(maildir, ".Archive", sub), 0o755))
		}

		// Archive sorts before INBOX: message 1 commits in Archive, then outer ShareLock
		// holder is terminated before INBOX's 2 messages run InsertMessagesFromImporterBatchWithRetry.
		name1, body1 := newGuardLossMaildirMessage(1, "ind-m1")
		path1 := filepath.Join(maildir, ".Archive", "cur", name1)
		require.NoError(t, os.WriteFile(path1, body1, 0o644))
		hash1 := helpers.HashContent(body1)

		var expectedFailed []string
		for k := 2; k <= 3; k++ {
			name, body := newGuardLossMaildirMessage(k, "ind-rest")
			p := filepath.Join(maildir, "cur", name)
			require.NoError(t, os.WriteFile(p, body, 0o644))
			expectedFailed = append(expectedFailed, p)
		}

		importer, err := NewImporter(f.ctx, maildir, localpart+"@"+domain, 1, f.rdb, f.store, ImporterOptions{
			CleanupDB:            true,
			BatchTransactionMode: false,
		})
		require.NoError(t, err)
		t.Cleanup(func() { importer.Close() })
		importer.rdb = &guardLossInsertDB{
			ResilientDatabase:      f.rdb,
			t:                      t,
			accountID:              accountID,
			lockHash:               hash1,
			terminateAfterBatchNum: 1,
		}

		out, runErr := runCapturingStdout(t, importer.Run)
		require.NoError(t, f.ctx.Err(), "operator context must remain active")
		require.Error(t, runErr)
		assert.Equal(t, "import completed with 2 failed messages", runErr.Error())

		assert.Equal(t, int64(3), importer.totalMessages)
		assert.Equal(t, int64(1), importer.importedMessages, "committed and SQLite-marked message 1 must be counted as imported")
		assert.Zero(t, importer.skippedMessages)
		assert.Equal(t, int64(2), importer.failedMessages)
		assert.ElementsMatch(t, expectedFailed, recordedFailedPaths(importer))

		assert.Contains(t, out, "Import Summary:")
		assert.Contains(t, out, "Imported:          1")
		assert.Contains(t, out, "Failed:            2")
		assert.Contains(t, out, "Failed Messages (2):")

		require.FileExists(t, filepath.Join(maildir, "sora-maildir.db"))
		imported, pending := uploadedCounts(t, maildir)
		assert.Equal(t, 1, imported)
		assert.Equal(t, 2, pending)
		assert.Equal(t, 1, countAccountLiveMessages(t, f.rdb, accountID))

		// Incremental retry imports the 2 remaining messages and cleans up sora-maildir.db.
		retryImporter, err := NewImporter(f.ctx, maildir, localpart+"@"+domain, 1, f.rdb, f.store, ImporterOptions{
			Incremental: true,
			CleanupDB:   true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { retryImporter.Close() })
		require.NoError(t, retryImporter.Run())
		assert.Equal(t, int64(2), retryImporter.importedMessages)
		assert.Zero(t, retryImporter.failedMessages)
		assert.Equal(t, 3, countAccountLiveMessages(t, f.rdb, accountID))
		assert.NoFileExists(t, filepath.Join(maildir, "sora-maildir.db"))
	})

	t.Run("individual fallback loop mid-chunk after message 1 commits credits message 1 and fails remaining", func(t *testing.T) {
		f := newRekeyFixture(t)
		accountID, domain, localpart := f.account("guard-insert-fallback")

		// Pre-insert a message occupying UID 3 in INBOX with UIDVALIDITY 100 so the
		// batch insert hits a UID unique violation on message 3 and falls back to
		// per-message InsertMessageFromImporterWithRetry.
		mb, err := f.rdb.GetMailboxByNameWithRetry(f.ctx, accountID, "INBOX")
		require.NoError(t, err)
		f.exec(`UPDATE mailboxes SET uid_validity = 100, highest_uid = 3 WHERE id = $1`, mb.ID)
		existingBody := f.body("existing-uid3")
		existingHash := helpers.HashContent(existingBody)
		f.put(helpers.NewS3Key(domain, localpart, existingHash), existingBody)
		existingID := f.insert(accountID, "INBOX", domain, localpart, existingHash, existingBody, "existing-uid3@example.com")
		f.exec(`UPDATE messages SET uid = 3 WHERE id = $1`, existingID)

		maildir := newCleanupDBMaildir(t, 0)
		var paths []string
		var hash1 string
		var uidList bytes.Buffer
		uidList.WriteString("3 V100 N4\n")
		for k := 1; k <= 3; k++ {
			name, body := newGuardLossMaildirMessage(k, "fallback")
			p := filepath.Join(maildir, "cur", name)
			require.NoError(t, os.WriteFile(p, body, 0o644))
			paths = append(paths, p)
			if k == 1 {
				hash1 = helpers.HashContent(body)
			}
			fmt.Fprintf(&uidList, "%d :%s\n", k, name[:len(name)-4])
		}
		require.NoError(t, os.WriteFile(filepath.Join(maildir, "dovecot-uidlist"), uidList.Bytes(), 0o644))

		importer, err := NewImporter(f.ctx, maildir, localpart+"@"+domain, 1, f.rdb, f.store, ImporterOptions{
			CleanupDB:            true,
			PreserveUIDs:         true,
			BatchTransactionMode: false,
		})
		require.NoError(t, err)
		t.Cleanup(func() { importer.Close() })
		importer.rdb = &guardLossInsertDB{
			ResilientDatabase:       f.rdb,
			t:                       t,
			accountID:               accountID,
			lockHash:                hash1,
			terminateAfterSingleNum: 1,
		}

		out, runErr := runCapturingStdout(t, importer.Run)
		require.NoError(t, f.ctx.Err(), "operator context must remain active")
		require.Error(t, runErr)
		assert.Equal(t, "import completed with 2 failed messages", runErr.Error())

		assert.Equal(t, int64(3), importer.totalMessages)
		assert.Equal(t, int64(1), importer.importedMessages)
		assert.Equal(t, int64(2), importer.failedMessages)
		assert.ElementsMatch(t, paths[1:], recordedFailedPaths(importer))
		assert.Contains(t, out, "Imported:          1")
		assert.Contains(t, out, "Failed:            2")
		require.FileExists(t, filepath.Join(maildir, "sora-maildir.db"))
	})

	t.Run("batch transaction mode rolls back and counts all uploaded messages on guard loss", func(t *testing.T) {
		f := newRekeyFixture(t)
		accountID, domain, localpart := f.account("guard-insert-batchtx")

		maildir := newCleanupDBMaildir(t, 0)
		var expectedPaths []string
		for k := 1; k <= 3; k++ {
			name, body := newGuardLossMaildirMessage(k, "batchtx")
			p := filepath.Join(maildir, "cur", name)
			require.NoError(t, os.WriteFile(p, body, 0o644))
			expectedPaths = append(expectedPaths, p)
		}

		// Terminate outer ShareLock holder right as the 3rd S3 upload completes (without
		// cancelling ctx during upload), so uploadBatchToS3 returns all 3 messages and
		// insertBatchToDBWithTransaction discovers the dead holder on S3 body admission.
		s3Store := &guardLossUploadStorage{
			FileBasedS3Mock:   f.store,
			t:                 t,
			rdb:               f.rdb,
			accountID:         accountID,
			terminateOnPutNum: 3,
			observeInUpload:   false,
		}

		importer, err := NewImporter(f.ctx, maildir, localpart+"@"+domain, 1, f.rdb, s3Store, ImporterOptions{
			CleanupDB:            true,
			BatchTransactionMode: true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { importer.Close() })

		out, runErr := runCapturingStdout(t, importer.Run)
		require.NoError(t, f.ctx.Err(), "operator context must remain active")
		require.Error(t, runErr)
		assert.Equal(t, "import completed with 3 failed messages", runErr.Error())

		assert.Equal(t, int64(3), importer.totalMessages)
		assert.Zero(t, importer.importedMessages)
		assert.Zero(t, importer.skippedMessages)
		assert.Equal(t, int64(3), importer.failedMessages)
		assert.ElementsMatch(t, expectedPaths, recordedFailedPaths(importer))

		assert.Contains(t, out, "Import Summary:")
		assert.Contains(t, out, "Failed:            3")
		assert.Contains(t, out, "Failed Messages (3):")

		require.FileExists(t, filepath.Join(maildir, "sora-maildir.db"))
		imported, pending := uploadedCounts(t, maildir)
		assert.Equal(t, 0, imported)
		assert.Equal(t, 3, pending)
		assert.Equal(t, 0, countAccountLiveMessages(t, f.rdb, accountID))
	})

	t.Run("earlier failed message does not swallow or under-count guard-lost batch", func(t *testing.T) {
		f := newRekeyFixture(t)
		accountID, domain, localpart := f.account("guard-insert-prior-fail")

		maildir := newCleanupDBMaildir(t, 0)
		for _, sub := range []string{"cur", "new", "tmp"} {
			require.NoError(t, os.MkdirAll(filepath.Join(maildir, ".Archive", sub), 0o755))
		}

		// Empty file fails during scan (failedMessages == 1 before importMessages runs).
		corruptPath := filepath.Join(maildir, "cur", "1700000000.M0P1.host:2,S")
		require.NoError(t, os.WriteFile(corruptPath, nil, 0o644))

		name1, body1 := newGuardLossMaildirMessage(1, "prior-m1")
		path1 := filepath.Join(maildir, ".Archive", "cur", name1)
		require.NoError(t, os.WriteFile(path1, body1, 0o644))
		hash1 := helpers.HashContent(body1)

		expectedFailed := []string{corruptPath}
		for k := 2; k <= 3; k++ {
			name, body := newGuardLossMaildirMessage(k, "prior-rest")
			p := filepath.Join(maildir, "cur", name)
			require.NoError(t, os.WriteFile(p, body, 0o644))
			expectedFailed = append(expectedFailed, p)
		}

		importer, err := NewImporter(f.ctx, maildir, localpart+"@"+domain, 1, f.rdb, f.store, ImporterOptions{
			CleanupDB:            true,
			BatchTransactionMode: false,
		})
		require.NoError(t, err)
		t.Cleanup(func() { importer.Close() })
		importer.rdb = &guardLossInsertDB{
			ResilientDatabase:      f.rdb,
			t:                      t,
			accountID:              accountID,
			lockHash:               hash1,
			terminateAfterBatchNum: 1,
		}

		out, runErr := runCapturingStdout(t, importer.Run)
		require.NoError(t, f.ctx.Err(), "operator context must remain active")
		require.Error(t, runErr)
		assert.Equal(t, "import completed with 3 failed messages", runErr.Error())

		assert.Equal(t, int64(3), importer.totalMessages)
		assert.Equal(t, int64(1), importer.importedMessages)
		assert.Zero(t, importer.skippedMessages)
		assert.Equal(t, int64(3), importer.failedMessages, "must count 1 earlier scan failure + 2 guard-lost messages")
		assert.ElementsMatch(t, expectedFailed, recordedFailedPaths(importer))

		assert.Contains(t, out, "Import Summary:")
		assert.Contains(t, out, "Imported:          1")
		assert.Contains(t, out, "Failed:            3")
		assert.Contains(t, out, "Failed Messages (3):")
		require.FileExists(t, filepath.Join(maildir, "sora-maildir.db"))
	})
}

func TestImporterOperatorInterruptKeepsExistingBehavior(t *testing.T) {
	t.Run("operator interrupt during upload leaves remaining work pending with zero failures", func(t *testing.T) {
		f := newRekeyFixture(t)
		accountID, domain, localpart := f.account("op-interrupt-upload")

		maildir := newCleanupDBMaildir(t, 0)
		for k := 1; k <= 3; k++ {
			name, body := newGuardLossMaildirMessage(k, "op-up")
			require.NoError(t, os.WriteFile(filepath.Join(maildir, "cur", name), body, 0o644))
		}

		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()

		s3Store := &guardLossUploadStorage{
			FileBasedS3Mock:   f.store,
			t:                 t,
			rdb:               f.rdb,
			accountID:         accountID,
			terminateOnPutNum: 2,
			cancelOperator:    cancel,
		}

		importer, err := NewImporter(ctx, maildir, localpart+"@"+domain, 1, f.rdb, s3Store, ImporterOptions{
			CleanupDB: true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { importer.Close() })

		err = importer.Run()
		require.ErrorIs(t, err, context.Canceled)
		assert.Zero(t, importer.importedMessages)
		assert.Zero(t, importer.failedMessages)
		assert.Empty(t, recordedFailedPaths(importer))
		require.FileExists(t, filepath.Join(maildir, "sora-maildir.db"))

		imported, pending := uploadedCounts(t, maildir)
		assert.Equal(t, 0, imported)
		assert.Equal(t, 3, pending)
	})

	t.Run("operator interrupt mid-insert credits committed message and leaves rest pending with zero failures", func(t *testing.T) {
		f := newRekeyFixture(t)
		accountID, domain, localpart := f.account("op-interrupt-insert")

		maildir := newCleanupDBMaildir(t, 0)
		for _, sub := range []string{"cur", "new", "tmp"} {
			require.NoError(t, os.MkdirAll(filepath.Join(maildir, ".Archive", sub), 0o755))
		}

		name1, body1 := newGuardLossMaildirMessage(1, "op-in-m1")
		require.NoError(t, os.WriteFile(filepath.Join(maildir, ".Archive", "cur", name1), body1, 0o644))
		hash1 := helpers.HashContent(body1)

		for k := 2; k <= 3; k++ {
			name, body := newGuardLossMaildirMessage(k, "op-in-rest")
			require.NoError(t, os.WriteFile(filepath.Join(maildir, "cur", name), body, 0o644))
		}

		ctx, cancel := context.WithCancel(f.ctx)
		defer cancel()

		importer, err := NewImporter(ctx, maildir, localpart+"@"+domain, 1, f.rdb, f.store, ImporterOptions{
			CleanupDB: true,
		})
		require.NoError(t, err)
		t.Cleanup(func() { importer.Close() })
		importer.rdb = &guardLossInsertDB{
			ResilientDatabase:      f.rdb,
			t:                      t,
			accountID:              accountID,
			lockHash:               hash1,
			terminateAfterBatchNum: 1,
			cancelOperator:         cancel,
		}

		err = importer.Run()
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, int64(1), importer.importedMessages)
		assert.Zero(t, importer.failedMessages)
		assert.Empty(t, recordedFailedPaths(importer))
		require.FileExists(t, filepath.Join(maildir, "sora-maildir.db"))

		imported, pending := uploadedCounts(t, maildir)
		assert.Equal(t, 1, imported)
		assert.Equal(t, 2, pending)
	})
}
