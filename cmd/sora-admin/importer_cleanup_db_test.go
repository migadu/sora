package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCleanupDBMaildir builds a maildir holding n message files and returns its path.
func newCleanupDBMaildir(t *testing.T, n int) string {
	t.Helper()
	maildirPath := filepath.Join(t.TempDir(), "Maildir")
	for _, dir := range []string{"cur", "new", "tmp"} {
		require.NoError(t, os.MkdirAll(filepath.Join(maildirPath, dir), 0755))
	}
	for k := 1; k <= n; k++ {
		name := fmt.Sprintf("1700000%03d.M%dP1.host:2,S", k, k)
		content := fmt.Sprintf("From: sender@example.com\r\nTo: user@example.com\r\nSubject: Message %d\r\nMessage-ID: <cleanup-%d@example.com>\r\n\r\nBody %d\r\n", k, k, k)
		require.NoError(t, os.WriteFile(filepath.Join(maildirPath, "cur", name), []byte(content), 0644))
	}
	return maildirPath
}

// newCleanupDBImporter returns an importer with --cleanup-db over maildirPath, wired
// to rdb and s3 (nil s3 = test mode, no uploads).
func newCleanupDBImporter(t *testing.T, ctx context.Context, maildirPath string, rdb resilientDB, s3 objectStorage) *Importer {
	t.Helper()
	importer, err := NewImporter(ctx, maildirPath, "user@example.com", 1, nil, nil, ImporterOptions{
		CleanupDB: true,
		TestMode:  s3 == nil,
	})
	require.NoError(t, err)
	t.Cleanup(func() { importer.Close() })
	importer.rdb = rdb
	if s3 != nil {
		importer.s3 = s3
	}
	return importer
}

// uploadedCounts reads the kept import database: how many files it records as
// imported, and how many are left for the next --incremental run.
func uploadedCounts(t *testing.T, maildirPath string) (imported, pending int) {
	t.Helper()
	importer, err := NewImporter(context.Background(), maildirPath, "user@example.com", 1, nil, nil, ImporterOptions{})
	require.NoError(t, err)
	defer importer.Close()
	require.NoError(t, importer.sqliteDB.QueryRow(`SELECT COUNT(*) FROM messages WHERE s3_uploaded = 1`).Scan(&imported))
	require.NoError(t, importer.sqliteDB.QueryRow(`SELECT COUNT(*) FROM messages WHERE s3_uploaded = 0`).Scan(&pending))
	return imported, pending
}

// cancelOnPutStorage stands in for S3: the first upload lands, then the operator
// presses Ctrl-C (the context is cancelled), as happens in the middle of a batch.
type cancelOnPutStorage struct {
	cancel context.CancelFunc
	puts   int
}

func (s *cancelOnPutStorage) Put(key string, reader io.Reader, size int64) error {
	s.puts++
	s.cancel()
	return nil
}
func (s *cancelOnPutStorage) Get(key string) (io.ReadCloser, error) { return nil, os.ErrNotExist }
func (s *cancelOnPutStorage) Exists(key string) (bool, string, error) {
	return false, "", nil
}
func (s *cancelOnPutStorage) Delete(key string) error                { return nil }
func (s *cancelOnPutStorage) Copy(sourcePath, destPath string) error { return nil }
func (s *cancelOnPutStorage) EnableEncryption(encryptionKey string) error {
	return nil
}

// ctxAwareDB answers account lookups the way the resilient database does: once the
// context is cancelled, the call fails with the context's error.
type ctxAwareDB struct {
	*mockResilientDatabase
}

func (m *ctxAwareDB) GetAccountIDByAddressWithRetry(ctx context.Context, address string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return m.mockResilientDatabase.GetAccountIDByAddressWithRetry(ctx, address)
}

// failingAccountLookupDB fails every account lookup, as a database that stays
// unreachable past the retries does: orphan recovery treats that as non-fatal, and
// the insert phase loses the whole batch.
type failingAccountLookupDB struct {
	*mockResilientDatabase
}

func (m *failingAccountLookupDB) GetAccountIDByAddressWithRetry(ctx context.Context, address string) (int64, error) {
	return 0, errors.New("simulated database unavailable")
}

// --cleanup-db removes sora-maildir.db, the record of which files are already
// imported. It must do so only after an import that succeeded: after a failed, partly
// failed or interrupted run the file is what lets the re-run (--incremental) import
// only what is missing instead of reading and uploading the whole maildir again.
func TestImportCleanupDBOnlyAfterSuccessfulRun(t *testing.T) {
	t.Run("successful run removes the database", func(t *testing.T) {
		maildirPath := newCleanupDBMaildir(t, 2)
		importer := newCleanupDBImporter(t, context.Background(), maildirPath, newMockResilientDatabase(), nil)

		require.NoError(t, importer.Run())
		assert.Equal(t, int64(2), importer.importedMessages)
		assert.NoFileExists(t, filepath.Join(maildirPath, "sora-maildir.db"))
	})

	t.Run("run with failed messages keeps the database", func(t *testing.T) {
		maildirPath := newCleanupDBMaildir(t, 2)
		rdb := newMockResilientDatabase()
		rdb.insertMessageShouldFail = true
		rdb.insertMessageError = errors.New("simulated insert failure")
		importer := newCleanupDBImporter(t, context.Background(), maildirPath, rdb, nil)

		require.Error(t, importer.Run())
		assert.FileExists(t, filepath.Join(maildirPath, "sora-maildir.db"),
			"a run with failed messages removed the import database")
	})

	t.Run("interrupted run keeps the database", func(t *testing.T) {
		maildirPath := newCleanupDBMaildir(t, 2)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		importer := newCleanupDBImporter(t, ctx, maildirPath, newMockResilientDatabase(), nil)

		require.Error(t, importer.Run())
		assert.FileExists(t, filepath.Join(maildirPath, "sora-maildir.db"),
			"an interrupted run removed the import database")
	})

	t.Run("run interrupted during the final batch fails and keeps the database", func(t *testing.T) {
		maildirPath := newCleanupDBMaildir(t, 2)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s3 := &cancelOnPutStorage{cancel: cancel}
		importer := newCleanupDBImporter(t, ctx, maildirPath, &ctxAwareDB{newMockResilientDatabase()}, s3)

		err := importer.Run()
		require.Equal(t, 1, s3.puts, "the second upload must see the cancellation")
		require.Error(t, err, "a run interrupted before its messages were imported reported success")
		assert.ErrorIs(t, err, context.Canceled)
		require.FileExists(t, filepath.Join(maildirPath, "sora-maildir.db"),
			"an interrupted run removed the import database")

		imported, pending := uploadedCounts(t, maildirPath)
		assert.Equal(t, 0, imported)
		assert.Equal(t, 2, pending, "the messages the interruption left out are recorded for the next run")
	})

	t.Run("run whose batch insert failed as a whole fails and keeps the database", func(t *testing.T) {
		maildirPath := newCleanupDBMaildir(t, 2)
		rdb := &failingAccountLookupDB{newMockResilientDatabase()}
		importer := newCleanupDBImporter(t, context.Background(), maildirPath, rdb, nil)

		err := importer.Run()
		require.Error(t, err, "a run that imported none of its messages reported success")
		assert.Equal(t, int64(2), importer.failedMessages)
		assert.FileExists(t, filepath.Join(maildirPath, "sora-maildir.db"),
			"a failed run removed the import database")
	})
}
