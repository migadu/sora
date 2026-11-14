package uploader

import (
	"context"
	"os"
	"path/filepath"
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
