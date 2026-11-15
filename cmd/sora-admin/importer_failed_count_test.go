package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rejectingStorage stands in for an S3 that refuses every upload. With cancel set,
// the operator also presses Ctrl-C (the context is cancelled) during the first one.
type rejectingStorage struct {
	cancel context.CancelFunc
	puts   atomic.Int64
}

func (s *rejectingStorage) Put(key string, reader io.Reader, size int64) error {
	s.puts.Add(1)
	if s.cancel != nil {
		s.cancel()
	}
	return errors.New("simulated S3 rejection")
}
func (s *rejectingStorage) Get(key string) (io.ReadCloser, error) { return nil, os.ErrNotExist }
func (s *rejectingStorage) Exists(key string) (bool, string, error) {
	return false, "", nil
}
func (s *rejectingStorage) Delete(key string) error                { return nil }
func (s *rejectingStorage) Copy(sourcePath, destPath string) error { return nil }
func (s *rejectingStorage) EnableEncryption(encryptionKey string) error {
	return nil
}

// newRejectingS3Importer returns an importer over maildirPath that uploads to s3.
func newRejectingS3Importer(t *testing.T, ctx context.Context, maildirPath string, jobs int, s3 objectStorage) *Importer {
	t.Helper()
	importer, err := NewImporter(ctx, maildirPath, "user@example.com", jobs, nil, s3, ImporterOptions{})
	require.NoError(t, err)
	t.Cleanup(func() { importer.Close() })
	importer.rdb = newMockResilientDatabase()
	return importer
}

// recordedFailedPaths returns the maildir paths the import recorded as failed, once
// per record.
func recordedFailedPaths(importer *Importer) []string {
	importer.failedPathsMutex.Lock()
	defer importer.failedPathsMutex.Unlock()
	var paths []string
	for _, f := range importer.failedPaths {
		paths = append(paths, f.path)
	}
	return paths
}

// recordedFailedReasons returns the reasons of the records recordedFailedPaths lists,
// in the same order.
func recordedFailedReasons(importer *Importer) []string {
	importer.failedPathsMutex.Lock()
	defer importer.failedPathsMutex.Unlock()
	var reasons []string
	for _, f := range importer.failedPaths {
		reasons = append(reasons, f.reason)
	}
	return reasons
}

// The upload phase counts every message it drops (read, decompress, size, parse or
// upload error) as it drops it. A batch none of whose messages reached the insert
// phase must not be counted again as a whole (#546).
func TestImportCountsEachMessageOfAFailedBatchOnce(t *testing.T) {
	t.Run("S3 rejects every upload", func(t *testing.T) {
		maildirPath := newCleanupDBMaildir(t, 2)
		s3 := &rejectingStorage{}
		importer := newRejectingS3Importer(t, context.Background(), maildirPath, 2, s3)

		err := importer.Run()
		require.Error(t, err)
		assert.Equal(t, "import completed with 2 failed messages", err.Error())
		assert.Equal(t, int64(2), importer.failedMessages,
			"the summary's Failed count differs from the messages that failed")
		assert.Len(t, recordedFailedPaths(importer), 2, "each failed message is listed once")
		assert.Zero(t, importer.importedMessages)

		imported, pending := uploadedCounts(t, maildirPath)
		assert.Equal(t, 0, imported)
		assert.Equal(t, 2, pending, "the failed messages are left for the next run")
	})

	// A message the cancellation stopped before its upload was never attempted: it is
	// not a failure, and the run reports the cancellation instead.
	t.Run("cancelled during the first upload", func(t *testing.T) {
		maildirPath := newCleanupDBMaildir(t, 2)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		s3 := &rejectingStorage{cancel: cancel}
		importer := newRejectingS3Importer(t, ctx, maildirPath, 1, s3)

		err := importer.Run()
		require.ErrorIs(t, err, context.Canceled)
		assert.Equal(t, int64(3), s3.puts.Load(), "only the first message is uploaded (with its retries)")
		assert.Equal(t, int64(1), importer.failedMessages,
			"a message the cancellation left unattempted was counted as failed")
		if assert.Len(t, recordedFailedPaths(importer), 1) {
			assert.Equal(t, "1700000001.M1P1.host:2,S", filepath.Base(recordedFailedPaths(importer)[0]))
		}
		assert.Zero(t, importer.importedMessages)

		imported, pending := uploadedCounts(t, maildirPath)
		assert.Equal(t, 0, imported)
		assert.Equal(t, 2, pending, "both messages are left for the next run")
	})
}

// A file the scan cannot read is reported by the scan. A cache row an earlier run left
// for it must not be read again by the import and reported a second time (#546).
func TestImportCountsAFileTheScanCouldNotReadOnce(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file whatever its permission bits")
	}
	const unreadable = "1700000001.M1P1.host:2,S"

	for _, tc := range []struct {
		name string
		// failFirst makes the first run's inserts fail, which leaves its rows pending.
		failFirst   bool
		incremental bool
	}{
		{name: "re-run of an imported maildir"},
		{name: "incremental retry of a failed run", failFirst: true, incremental: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			maildirPath := newCleanupDBMaildir(t, 2)
			first := newMockResilientDatabase()
			if tc.failFirst {
				first.insertMessageShouldFail = true
				first.insertMessageError = errors.New("simulated insert failure")
			}
			_ = newTestModeImporter(t, maildirPath, first, ImporterOptions{}).Run()

			path := filepath.Join(maildirPath, "cur", unreadable)
			require.NoError(t, os.Chmod(path, 0))
			t.Cleanup(func() { _ = os.Chmod(path, 0644) })

			importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{Incremental: tc.incremental})
			err := importer.Run()
			require.Error(t, err)
			assert.Equal(t, "import completed with 1 failed messages", err.Error())
			assert.Equal(t, int64(1), importer.failedMessages,
				"the summary's Failed count differs from the messages that failed")
			if paths := recordedFailedPaths(importer); assert.Len(t, paths, 1, "each failed message is listed once") {
				assert.Equal(t, unreadable, filepath.Base(paths[0]))
			}
			assert.Equal(t, int64(1), importer.importedMessages, "the readable message is imported")
		})
	}
}
