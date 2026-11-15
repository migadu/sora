package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cachedSizeMessage returns a message of about size bytes.
func cachedSizeMessage(subject string, size int) []byte {
	header := fmt.Sprintf("From: sender@example.com\r\nTo: user@example.com\r\nSubject: %s\r\nMessage-ID: <%s@example.com>\r\n\r\n", subject, strings.ToLower(subject))
	return []byte(header + strings.Repeat("x", size) + "\r\n")
}

// failureReasons returns the reasons the run gave for failing path.
func failureReasons(importer *Importer, path string) []string {
	importer.failedPathsMutex.Lock()
	defer importer.failedPathsMutex.Unlock()
	var reasons []string
	for _, f := range importer.failedPaths {
		if f.path == path {
			reasons = append(reasons, f.reason)
		}
	}
	return reasons
}

// newMaildirWith returns a maildir holding files (name -> content) in cur/.
func newMaildirWith(t *testing.T, files map[string][]byte) string {
	t.Helper()
	maildirPath := filepath.Join(t.TempDir(), "Maildir")
	for _, dir := range []string{"cur", "new", "tmp"} {
		require.NoError(t, os.MkdirAll(filepath.Join(maildirPath, dir), 0755))
	}
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(maildirPath, "cur", name), content, 0644))
	}
	return maildirPath
}

// The scan refuses a message above the import message limit before it caches it in
// sora-maildir.db, but the import phase imports every cached row, including one an
// earlier run took under a higher limit and kept (an interrupted or partly failed
// run). Such a message must not be imported, and is reported as failed once (#755).
func TestImportRefusesACachedMessageAboveTheLimit(t *testing.T) {
	const limit = 4 << 10
	const smallName = "1700000001.M1P1.host:2,S"
	const bigName = "1700000002.M2P1.host:2,S"

	// newCachedMaildir returns a maildir holding a message within the limit and one
	// above it, both cached by an earlier run under a higher limit that stopped
	// before importing anything.
	newCachedMaildir := func(t *testing.T) (maildirPath, bigPath string) {
		t.Helper()
		maildirPath = newMaildirWith(t, map[string][]byte{
			smallName: cachedSizeMessage("Small", 100),
			bigName:   cachedSizeMessage("Big", 2*limit),
		})
		bigPath = filepath.Join(maildirPath, "cur", bigName)

		earlier := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{MaxMessageSize: 4 * limit})
		require.NoError(t, earlier.scanMaildir())
		require.NoError(t, earlier.Close())
		_, pending := uploadedCounts(t, maildirPath)
		require.Equal(t, 2, pending, "the earlier run cached both messages")
		return maildirPath, bigPath
	}

	check := func(t *testing.T, importer *Importer, bigPath string) {
		t.Helper()
		require.Error(t, importer.Run(), "a run that refused a message reported success")
		assert.Equal(t, int64(1), importer.importedMessages,
			"imported the message above the limit from the earlier run's cached row")
		assert.Equal(t, int64(1), importer.failedMessages)
		reasons := failureReasons(importer, bigPath)
		if assert.Len(t, reasons, 1, "the message above the limit is reported as failed once") {
			assert.Contains(t, reasons[0], "message too large")
		}
	}

	for _, incremental := range []bool{false, true} {
		t.Run(fmt.Sprintf("refused by the scan, incremental=%v", incremental), func(t *testing.T) {
			maildirPath, bigPath := newCachedMaildir(t)
			importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(),
				ImporterOptions{MaxMessageSize: limit, Incremental: incremental})
			check(t, importer, bigPath)
		})
	}

	// With --paths-file the scan visits only the listed files, while the import phase
	// still imports every cached row.
	t.Run("not visited by the scan", func(t *testing.T) {
		maildirPath, bigPath := newCachedMaildir(t)
		pathsFile := filepath.Join(t.TempDir(), "paths")
		require.NoError(t, os.WriteFile(pathsFile, []byte("cur/"+smallName+"\n"), 0644))
		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(),
			ImporterOptions{MaxMessageSize: limit, PathsFile: pathsFile})
		check(t, importer, bigPath)
	})
}

// A file rewritten between the scan and the import is imported from the bytes the
// import reads, under their hash; their size must pass the same limit (#755).
func TestImportRefusesAFileGrownAboveTheLimitSinceTheScan(t *testing.T) {
	const limit = 4 << 10
	maildirPath := newMaildirWith(t, map[string][]byte{
		"1700000001.M1P1.host:2,S": cachedSizeMessage("Steady", 100),
		"1700000002.M2P1.host:2,S": cachedSizeMessage("Grown", 100),
	})
	grownPath := filepath.Join(maildirPath, "cur", "1700000002.M2P1.host:2,S")

	importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{MaxMessageSize: limit})
	require.NoError(t, importer.lookupAccount())
	require.NoError(t, importer.scanMaildir())
	require.NoError(t, os.WriteFile(grownPath, cachedSizeMessage("Grown", 2*limit), 0644))

	importer.totalMessages = 2
	require.NoError(t, importer.importMessages())
	assert.Equal(t, int64(1), importer.importedMessages, "imported a file grown above the limit since the scan")
	assert.Equal(t, int64(1), importer.failedMessages)
	reasons := failureReasons(importer, grownPath)
	if assert.Len(t, reasons, 1) {
		assert.Contains(t, reasons[0], "message too large")
	}
}

// The upload must validate the current decoded bytes, rather than a stale cache
// size or a compressed file's on-disk size. A paths file leaves the cached row
// outside this run's scan, so only the upload's check can decide it.
func TestImportChecksCurrentBytesForUnscannedCachedFile(t *testing.T) {
	const limit = 4 << 10
	const steady = "1700000001.M1P1.host:2,S"
	const changed = "1700000002.M2P1.host:2,S"
	big := cachedSizeMessage("Changed", 2*limit)
	for _, tc := range []struct {
		name     string
		content  []byte
		wantFail bool
	}{
		{"stale larger cached size now fits", cachedSizeMessage("Changed", 100), false},
		{"exact decoded limit", append(cachedSizeMessage("Changed", 100), make([]byte, limit-len(cachedSizeMessage("Changed", 100)))...), false},
		{"compressed bytes fit but decoded message does not", mustGzip(big), true},
		{"file is now empty", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			maildirPath := newMaildirWith(t, map[string][]byte{
				steady:  cachedSizeMessage("Steady", 100),
				changed: big,
			})
			earlier := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{MaxMessageSize: 4 * limit})
			require.NoError(t, earlier.scanMaildir())
			require.NoError(t, earlier.Close())
			changedPath := filepath.Join(maildirPath, "cur", changed)
			require.NoError(t, os.WriteFile(changedPath, tc.content, 0644))
			pathsFile := filepath.Join(t.TempDir(), "paths")
			require.NoError(t, os.WriteFile(pathsFile, []byte("cur/"+steady+"\n"), 0644))
			importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(),
				ImporterOptions{MaxMessageSize: limit, PathsFile: pathsFile})
			err := importer.Run()
			if tc.wantFail {
				require.Error(t, err)
				assert.Equal(t, int64(1), importer.importedMessages)
				assert.Equal(t, int64(1), importer.failedMessages)
				assert.Len(t, failureReasons(importer, changedPath), 1)
			} else {
				require.NoError(t, err)
				assert.Equal(t, int64(2), importer.importedMessages)
				assert.Zero(t, importer.failedMessages)
			}
		})
	}
}

// The upload reads every file it imports again, and that file may have grown since the
// scan sized it, or this run's scan may not have visited it (--paths-file). Refusing a
// file above the import message limit must cost memory in proportion to that limit, not
// to the file: reading all of it first lets each upload worker allocate a whole changed
// file, or a compressed one's full expansion up to the 256 MiB decompression bound (#834).
func TestUploadReadsNoMoreOfAChangedFileThanTheLimit(t *testing.T) {
	const limit = 4 << 10
	const grown = 64 << 20
	const ceiling = 4 << 20
	for _, tc := range []struct {
		name string
		grow func(t *testing.T, path string)
	}{
		{"plain file grown", func(t *testing.T, path string) {
			require.NoError(t, os.Truncate(path, grown))
		}},
		{"compressed file", func(t *testing.T, path string) {
			onDisk := gzipOfSize(t, "From: sender@example.com\r\nSubject: Grown\r\n\r\n", grown)
			require.NoError(t, os.WriteFile(path, onDisk, 0644))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			maildirPath, name := newSingleMessageMaildir(t, cachedSizeMessage("Grown", 100))
			path := filepath.Join(maildirPath, "cur", name)
			importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{MaxMessageSize: limit})
			require.NoError(t, importer.scanMaildir())
			var msg msgInfo
			require.NoError(t, importer.sqliteDB.QueryRow(`SELECT path, filename, hash, size, mailbox FROM messages`).
				Scan(&msg.path, &msg.filename, &msg.hash, &msg.size, &msg.mailbox))
			tc.grow(t, path)

			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			uploaded := importer.uploadBatchToS3([]msgInfo{msg})
			runtime.ReadMemStats(&after)

			assert.Empty(t, uploaded, "uploaded a message above the limit")
			if reasons := failureReasons(importer, path); assert.Len(t, reasons, 1) {
				assert.Contains(t, reasons[0], "message too large")
			}
			if alloc := after.TotalAlloc - before.TotalAlloc; alloc > ceiling {
				t.Errorf("refusing a %d-byte message above the %d-byte limit allocated %d bytes, want under %d",
					grown, limit, alloc, ceiling)
			}
		})
	}
}
