package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A maildir's owner can make any file in it a named pipe (mkfifo), and rsync -a copies
// one as it is (--specials). Opening a FIFO for reading waits until something opens it
// for writing, and cancelling the run does not end that wait. Every file the import
// reads from the maildir, or from --sieve, is read only if it is a regular file; one
// that is not is refused without waiting (#1608).

// fifoWait is how long a call that meets a FIFO is given to return.
const fifoWait = 3 * time.Second

// mkfifo makes a named pipe at path.
func mkfifo(t *testing.T, path string) {
	t.Helper()
	require.NoError(t, syscall.Mkfifo(path, 0644))
}

// returnsWithin reports whether fn returns within fifoWait. If it does not, fifo is
// opened for writing until fn returns, which ends an open of it that waits for a
// writer, so neither fn nor the test's cleanup is left waiting.
func returnsWithin(t *testing.T, fifo string, fn func()) bool {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(fifoWait):
	}
	for {
		if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			w.Close()
		}
		select {
		case <-done:
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func TestScanMaildirRefusesAMessageFileThatIsAFIFO(t *testing.T) {
	const inboxName = "1700000001.M1P1.host:2,S"
	const fifoName = "1700000002.M2P1.host:2,S"

	for _, tc := range []struct {
		name string
		// fifo makes the FIFO message at path in maildirPath, and returns the path
		// --paths-file lists, or "" to walk the maildir.
		fifo func(t *testing.T, maildirPath, path string) (pathsFile string)
	}{
		{"FIFO", func(t *testing.T, maildirPath, path string) string {
			mkfifo(t, path)
			return ""
		}},
		{"link to a FIFO within the maildir", func(t *testing.T, maildirPath, path string) string {
			target := filepath.Join(maildirPath, "tmp", "1700000003.M3P1.host")
			mkfifo(t, target)
			require.NoError(t, os.Symlink(relativeLink(t, path, target), path))
			return ""
		}},
		{"FIFO in --paths-file", func(t *testing.T, maildirPath, path string) string {
			mkfifo(t, path)
			pathsFile := filepath.Join(t.TempDir(), "paths.txt")
			paths := filepath.Join(maildirPath, "cur", inboxName) + "\n" + path + "\n"
			require.NoError(t, os.WriteFile(pathsFile, []byte(paths), 0644))
			return pathsFile
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			maildirPath := newMaildirWith(t, map[string][]byte{inboxName: cachedSizeMessage("One", 100)})
			path := filepath.Join(maildirPath, "cur", fifoName)
			pathsFile := tc.fifo(t, maildirPath, path)

			importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{PathsFile: pathsFile})
			var err error
			require.True(t, returnsWithin(t, path, func() { err = importer.scanMaildir() }),
				"the scan waited on a message file that is a FIFO")
			require.NoError(t, err)

			assert.Equal(t, map[string]string{filepath.Join(maildirPath, "cur", inboxName): "INBOX"},
				scannedMessages(t, importer), "a message file that is a FIFO was cached for import")
			assert.Len(t, failureReasons(importer, path), 1, "the FIFO is not refused by path")
		})
	}
}

// A folder needs only one of cur/ and new/ to be scanned (isMaildirFolder), and the
// other may be a FIFO: listing it must not wait on it.
func TestScanMaildirSkipsAMessageDirectoryThatIsAFIFO(t *testing.T) {
	const inboxName = "1700000001.M1P1.host:2,S"

	for _, subDir := range []string{"cur", "new"} {
		t.Run(subDir, func(t *testing.T) {
			maildirPath := newMaildirWith(t, nil)
			other := "new"
			if subDir == "new" {
				other = "cur"
			}
			require.NoError(t, os.WriteFile(filepath.Join(maildirPath, other, inboxName), cachedSizeMessage("One", 100), 0644))
			fifo := filepath.Join(maildirPath, subDir)
			require.NoError(t, os.Remove(fifo))
			mkfifo(t, fifo)

			importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
			logs := &importLogBuffer{}
			prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
			var err error
			returned := returnsWithin(t, fifo, func() { err = importer.scanMaildir() })
			logger.Swap(prev)
			require.True(t, returned, "the scan waited on a message directory that is a FIFO")
			require.NoError(t, err)

			assert.Equal(t, map[string]string{filepath.Join(maildirPath, other, inboxName): "INBOX"}, scannedMessages(t, importer))
			assert.Contains(t, logs.String(), fifo, "the FIFO was skipped without a warning naming it")
		})
	}
}

// The import phase and the dry run read every cached row again, by the path the
// cache holds: the file there may have been replaced by a FIFO since the scan.
func TestImportRefusesACachedMessageThatIsNowAFIFO(t *testing.T) {
	const name = "1700000001.M1P1.host:2,S"

	// cachedThenFIFO returns an importer whose scan cached the maildir's message, and
	// the message's path, now a FIFO.
	cachedThenFIFO := func(t *testing.T) (*Importer, string) {
		t.Helper()
		maildirPath := newMaildirWith(t, map[string][]byte{name: cachedSizeMessage("Kept", 100)})
		path := filepath.Join(maildirPath, "cur", name)
		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{})
		require.NoError(t, importer.lookupAccount())
		require.NoError(t, importer.scanMaildir())
		require.Equal(t, "INBOX", scannedMessages(t, importer)[path])

		require.NoError(t, os.Remove(path))
		mkfifo(t, path)
		importer.totalMessages = 1
		return importer, path
	}

	t.Run("import", func(t *testing.T) {
		importer, path := cachedThenFIFO(t)
		var err error
		require.True(t, returnsWithin(t, path, func() { err = importer.importMessages() }),
			"the import waited on a cached message that is now a FIFO")
		require.NoError(t, err)
		assert.Zero(t, importer.importedMessages)
		assert.Len(t, failureReasons(importer, path), 1, "the FIFO is not refused by path")
	})

	t.Run("dry run", func(t *testing.T) {
		importer, path := cachedThenFIFO(t)
		var err error
		require.True(t, returnsWithin(t, path, func() { err = importer.performDryRun() }),
			"the dry run waited on a cached message that is now a FIFO")
		require.NoError(t, err)
	})
}

func TestImportReadsNoMaildirMetadataFileThatIsAFIFO(t *testing.T) {
	const name = "1700000001.M1P1.host:2,a"

	t.Run("subscriptions", func(t *testing.T) {
		maildirPath := newMaildirWith(t, nil)
		fifo := filepath.Join(maildirPath, "subscriptions")
		mkfifo(t, fifo)

		mockDB := &recordingSubMockDB{mockResilientDatabase: newMockResilientDatabase()}
		importer := newTestModeImporter(t, maildirPath, mockDB, ImporterOptions{Dovecot: true})
		require.NoError(t, importer.lookupAccount())

		var err error
		require.True(t, returnsWithin(t, fifo, func() { err = importer.processSubscriptions() }),
			"the import waited on a subscriptions file that is a FIFO")
		assert.Error(t, err)
		assert.Empty(t, mockDB.subscribed)
	})

	t.Run("root dovecot-keywords", func(t *testing.T) {
		maildirPath := newMaildirWith(t, nil)
		fifo := filepath.Join(maildirPath, "dovecot-keywords")
		mkfifo(t, fifo)

		var importer *Importer
		var err error
		returned := returnsWithin(t, fifo, func() {
			importer, err = NewImporter(context.Background(), maildirPath, "user@example.com", 1, nil, nil,
				ImporterOptions{TestMode: true, Dovecot: true})
		})
		if importer != nil {
			t.Cleanup(func() { importer.Close() })
		}
		require.True(t, returned, "the import waited on a dovecot-keywords file that is a FIFO")
		require.NoError(t, err)
		assert.Empty(t, importer.dovecotKeywords)
	})

	t.Run("folder dovecot-keywords", func(t *testing.T) {
		maildirPath := newMaildirWith(t, nil)
		addMaildirFolder(t, maildirPath, ".Work", name, cachedSizeMessage("One", 100))
		fifo := filepath.Join(maildirPath, ".Work", "dovecot-keywords")
		mkfifo(t, fifo)

		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{Dovecot: true})

		var keywords map[int]string
		require.True(t, returnsWithin(t, fifo, func() {
			keywords = importer.keywordsForMessagePath(filepath.Join(maildirPath, ".Work", "cur", name))
		}), "the import waited on a folder's dovecot-keywords file that is a FIFO")
		assert.Empty(t, keywords)
	})

	t.Run("dovecot-uidlist", func(t *testing.T) {
		maildirPath := newMaildirWith(t, map[string][]byte{name: cachedSizeMessage("One", 100)})
		fifo := filepath.Join(maildirPath, "dovecot-uidlist")
		mkfifo(t, fifo)

		importer := newTestModeImporter(t, maildirPath, newMockResilientDatabase(), ImporterOptions{PreserveUIDs: true})

		var err error
		require.True(t, returnsWithin(t, fifo, func() { err = importer.scanMaildir() }),
			"the scan waited on a dovecot-uidlist file that is a FIFO")
		require.NoError(t, err)
		assert.Empty(t, importer.dovecotUIDLists)
	})
}

func TestImportSieveScriptRefusesAFIFO(t *testing.T) {
	sievePath := filepath.Join(t.TempDir(), ".dovecot.sieve")
	mkfifo(t, sievePath)

	rdb := &sieveRecordingDB{mockResilientDatabase: newMockResilientDatabase()}
	importer := newTestModeImporter(t, newMaildirWith(t, nil), rdb, ImporterOptions{SievePath: sievePath})
	require.NoError(t, importer.lookupAccount())

	var err error
	require.True(t, returnsWithin(t, sievePath, func() { err = importer.importSieveScript() }),
		"the import waited on a --sieve file that is a FIFO")
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), sievePath, "the refusal does not name the file")
	}
	assert.Empty(t, rdb.stored)
}
