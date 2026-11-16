package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// metadataFileSize is the size of the sparse dovecot-keywords and subscriptions files
// below: far above any real one, at no cost in disk.
const metadataFileSize = 64 << 20

// metadataReadBudget is how much a read of such a file may allocate: a fraction of
// its size, so a read of the whole file does not fit.
const metadataReadBudget = metadataFileSize / 2

// newSparseFile creates path as a file of size bytes that occupies no disk.
func newSparseFile(t *testing.T, path string, size int64) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, nil, 0644))
	require.NoError(t, os.Truncate(path, size))
}

// allocatedDuring returns how many bytes f allocated.
func allocatedDuring(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// captureLogs sends the log at level and above to the returned buffer until the test
// ends.
func captureLogs(t *testing.T, level slog.Level) *importLogBuffer {
	t.Helper()
	logs := &importLogBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: level})))
	t.Cleanup(func() { logger.Swap(prev) })
	return logs
}

// A dovecot-keywords file left in the export's destination is read back to keep its
// numbering, but whoever can write there decides its size: the read must stop far
// short of a huge file, and the file must be named in a warning and replaced (#1672).
func TestExportKeywordsReadIsBounded(t *testing.T) {
	exporter, dest := newLinkTestExporter(t, nil, ExporterOptions{Dovecot: true})
	keywordsPath := filepath.Join(dest, "dovecot-keywords")
	newSparseFile(t, keywordsPath, metadataFileSize)
	logs := captureLogs(t, slog.LevelWarn)

	var err error
	allocated := allocatedDuring(func() {
		err = exporter.prepareKeywords("INBOX", []db.Message{{UID: 1, CustomFlags: []string{"$Work"}}})
	})
	require.NoError(t, err)

	assert.Less(t, allocated, uint64(metadataReadBudget), "the whole dovecot-keywords file was read into memory")
	got, err := os.ReadFile(keywordsPath)
	require.NoError(t, err)
	assert.Equal(t, "0 $Work\n", string(got), "the oversized dovecot-keywords was not replaced")
	assert.Contains(t, logs.String(), keywordsPath, "the oversized dovecot-keywords was replaced without a warning naming it")
}

// The import reads the root and every folder's dovecot-keywords, which the maildir's
// owner wrote: the read must stop far short of a huge file, which is named and
// ignored, and the import goes on without its keywords (#1672).
func TestImportKeywordsReadIsBounded(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		maildirPath := newMaildirWith(t, nil)
		keywordsPath := filepath.Join(maildirPath, "dovecot-keywords")
		newSparseFile(t, keywordsPath, metadataFileSize)
		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
		captureLogs(t, slog.LevelError)

		var err error
		allocated := allocatedDuring(func() { err = importer.parseDovecotKeywords() })

		assert.Less(t, allocated, uint64(metadataReadBudget), "the whole dovecot-keywords file was read into memory")
		if assert.Error(t, err, "an oversized dovecot-keywords was read") {
			assert.Contains(t, err.Error(), keywordsPath, "the error does not name the file")
		}
		assert.Empty(t, importer.dovecotKeywords)
	})

	t.Run("folder", func(t *testing.T) {
		maildirPath := newMaildirWith(t, nil)
		for _, dir := range []string{"cur", "new", "tmp"} {
			require.NoError(t, os.MkdirAll(filepath.Join(maildirPath, ".Sent", dir), 0755))
		}
		keywordsPath := filepath.Join(maildirPath, ".Sent", "dovecot-keywords")
		newSparseFile(t, keywordsPath, metadataFileSize)
		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{Dovecot: true})
		logs := captureLogs(t, slog.LevelWarn)

		var keywords map[int]string
		allocated := allocatedDuring(func() {
			keywords = importer.keywordsForMessagePath(filepath.Join(maildirPath, ".Sent", "cur", "1700000001.M1P1.host:2,Sa"))
		})

		assert.Less(t, allocated, uint64(metadataReadBudget), "the whole dovecot-keywords file was read into memory")
		assert.Empty(t, keywords)
		assert.Contains(t, logs.String(), keywordsPath, "the oversized dovecot-keywords was ignored without a warning naming it")
	})
}

// The import reads the subscriptions file the maildir's owner wrote: the read must
// stop far short of a huge file, which is named and ignored (#1672).
func TestImportSubscriptionsReadIsBounded(t *testing.T) {
	maildirPath := newMaildirWith(t, nil)
	subscriptionsPath := filepath.Join(maildirPath, "subscriptions")
	newSparseFile(t, subscriptionsPath, metadataFileSize)
	importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{Dovecot: true})
	require.NoError(t, importer.lookupAccount())
	captureLogs(t, slog.LevelError)

	var err error
	allocated := allocatedDuring(func() { err = importer.processSubscriptions() })

	assert.Less(t, allocated, uint64(metadataReadBudget), "the whole subscriptions file was read into memory")
	if assert.Error(t, err, "an oversized subscriptions file was read") {
		assert.Contains(t, err.Error(), subscriptionsPath, "the error does not name the file")
	}
}

// Malformed dovecot-keywords lines are skipped, but the file's writer decides how long
// and how many they are: the log must not grow with them. A line whose index no a-z
// letter can name is skipped too, as Dovecot skips it (#1672).
func TestDovecotKeywordsMalformedLinesAreLoggedShortened(t *testing.T) {
	var content strings.Builder
	content.WriteString("0 $Work\n")
	content.WriteString(strings.Repeat("x", 16<<10) + "\n")
	for range 1000 {
		content.WriteString("y\n")
	}
	content.WriteString("notanumber $Other\n")
	content.WriteString("26 $Beyond\n")
	content.WriteString("-1 $Before\n")
	content.WriteString("25 $Last\n")

	maildirPath := newMaildirWith(t, nil)
	keywordsPath := filepath.Join(maildirPath, "dovecot-keywords")
	require.NoError(t, os.WriteFile(keywordsPath, []byte(content.String()), 0644))
	importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
	logs := captureLogs(t, slog.LevelInfo)

	require.NoError(t, importer.parseDovecotKeywords())

	assert.Equal(t, map[int]string{0: "$Work", 25: "$Last"}, importer.dovecotKeywords)
	assert.Contains(t, logs.String(), keywordsPath, "the malformed lines were skipped without a warning naming the file")
	assert.Less(t, len(logs.String()), 2048, "the log grows with the malformed lines")
}
