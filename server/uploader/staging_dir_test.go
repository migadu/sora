package uploader

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestStagingAccountDirOutlivesItsLastBody replays, one step at a time, a delivery
// staging a body for an account while the uploader removes that account's last staged
// file (#573). StoreLocally creates the account directory with MkdirAll and then opens
// its .tmp inside it; nothing orders those two calls against the uploader, so if
// removing the last file also removes the now empty directory, the delivery's open
// fails with ENOENT and LMTP answers 451. Both ways a staged file leaves the spool are
// covered: an upload completing (RemoveLocalFile) and the orphan sweep.
func TestStagingAccountDirOutlivesItsLastBody(t *testing.T) {
	const (
		accountID = int64(108)
		lastHash  = "f76ce87800000000000000000000000000000000000000000000000000000001"
		nextHash  = "f76ce87800000000000000000000000000000000000000000000000000000002"
	)

	removers := map[string]func(t *testing.T, w *UploadWorker, path string){
		"upload completed": func(t *testing.T, w *UploadWorker, path string) {
			require.NoError(t, w.RemoveLocalFile(path))
		},
		"orphan sweep": func(t *testing.T, w *UploadWorker, path string) {
			// Old enough for the sweep, and no pending_uploads row: an orphan.
			old := time.Now().Add(-2 * time.Hour)
			require.NoError(t, os.Chtimes(path, old, old))
			w.rdb = new(mockUploaderDB)
			require.NoError(t, w.cleanupOrphanedFiles(context.Background()))
		},
	}

	for name, remove := range removers {
		t.Run(name, func(t *testing.T) {
			w := &UploadWorker{path: t.TempDir()}

			// The account's last staged body.
			last, err := w.StoreLocally(lastHash, accountID, []byte("last staged body"))
			require.NoError(t, err)

			// A delivery for the same account runs StoreLocally's MkdirAll: the
			// directory is there, so it returns at once.
			next := w.FilePath(nextHash, accountID)
			require.NoError(t, os.MkdirAll(filepath.Dir(next), 0755))

			// The uploader is done with the last body before the delivery opens its file.
			remove(t, w, *last)
			_, err = os.Stat(*last)
			require.True(t, os.IsNotExist(err), "the last staged body must have left the spool")

			// StoreLocally's OpenFile of the .tmp.
			f, err := os.OpenFile(next+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			require.NoError(t, err, "a delivery that has passed MkdirAll must find the account's staging directory still there")
			require.NoError(t, f.Close())
		})
	}
}

// TestConcurrentStagingsOfOneBody stages one body for one account from several
// goroutines at once, as two sessions do when they APPEND the same bytes and both pass
// their callers' Stat before either has renamed its file into place (#752). Every
// staging must succeed, the staged body must be complete, and no temporary file may be
// left behind. With one shared <hash>.tmp, one writer's rename moved the name away from
// under the other, whose own rename then failed with ENOENT (IMAP NO, LMTP 451).
func TestConcurrentStagingsOfOneBody(t *testing.T) {
	const (
		accountID = int64(752)
		writers   = 8
		rounds    = 10
	)
	w := &UploadWorker{path: t.TempDir()}
	body := bytes.Repeat([]byte("the same message bytes\r\n"), 4096)

	for round := 1; round <= rounds; round++ {
		hash := fmt.Sprintf("%064x", round)

		start := make(chan struct{})
		errs := make(chan error, writers)
		var wg sync.WaitGroup
		for range writers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := w.StoreLocally(hash, accountID, body)
				errs <- err
			}()
		}
		close(start)
		wg.Wait()
		close(errs)

		for err := range errs {
			require.NoError(t, err, "round %d: a concurrent staging of the same body must succeed", round)
		}
		got, err := os.ReadFile(w.FilePath(hash, accountID))
		require.NoError(t, err)
		require.True(t, bytes.Equal(body, got), "round %d: staged body has %d bytes, want the complete %d", round, len(got), len(body))
	}

	entries, err := os.ReadDir(filepath.Dir(w.FilePath(fmt.Sprintf("%064x", 1), accountID)))
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	require.Len(t, names, rounds, "only the staged bodies may remain, no temporary files: %v", names)
}

func TestStagingRenameFailureCleansTemporaryFileAndCanRetry(t *testing.T) {
	const hash = "f76ce87800000000000000000000000000000000000000000000000000000814"
	w := &UploadWorker{path: t.TempDir()}
	path := w.FilePath(hash, 814)
	body := []byte("complete staged body\r\n")
	// Renaming a regular file over a directory must fail after the temporary
	// file has been fully written and closed.
	require.NoError(t, os.MkdirAll(path, 0755))
	_, err := w.StoreLocally(hash, 814, body)
	require.Error(t, err)
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1, "the failed rename must remove only its own temporary file")
	require.True(t, entries[0].IsDir(), "the failed rename must preserve the destination")
	require.Equal(t, int64(0), w.currentStagingSize)

	require.NoError(t, os.Remove(path))
	_, err = w.StoreLocally(hash, 814, body)
	require.NoError(t, err)
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, body, got)
	require.Equal(t, int64(len(body)), w.currentStagingSize)
	entries, err = os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	require.Len(t, entries, 1, "a retry leaves only the completed body")
}

func TestUniqueStagingTempFilesRespectCleanupGraceAndCancellation(t *testing.T) {
	const hash = "f76ce87800000000000000000000000000000000000000000000000000000814"
	w := &UploadWorker{path: t.TempDir()}
	path, err := w.StoreLocally(hash, 814, []byte("complete staged body\r\n"))
	require.NoError(t, err)
	oldTemp := *path + ".0123456789abcdef.tmp"
	recentTemp := *path + ".fedcba9876543210.tmp"
	for _, name := range []string{oldTemp, recentTemp} {
		require.NoError(t, os.WriteFile(name, []byte("unfinished body"), 0644))
	}
	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(oldTemp, old, old))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.NoError(t, w.cleanupOrphanedFiles(ctx))
	_, err = os.Stat(oldTemp)
	require.NoError(t, err, "a canceled cleanup must leave even an old temporary file alone")

	require.NoError(t, w.cleanupOrphanedFiles(context.Background()))
	_, err = os.Stat(oldTemp)
	require.True(t, os.IsNotExist(err), "a crash leftover with the new suffix must be swept")
	for _, name := range []string{recentTemp, *path, filepath.Dir(*path)} {
		_, err = os.Stat(name)
		require.NoError(t, err, "cleanup must preserve recent files and the account directory")
	}
}
