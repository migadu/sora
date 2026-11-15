package uploader

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// refuseHardLinks makes LinkStaged find no hard link, as across filesystems.
func refuseHardLinks(t *testing.T) {
	t.Helper()
	linkFile = func(oldname, newname string) error {
		return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EXDEV}
	}
	t.Cleanup(func() { linkFile = os.Link })
}

// requireNoTemporaryFiles fails if a staging temporary file is left in dir.
func requireNoTemporaryFiles(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return
	}
	require.NoError(t, err)
	for _, e := range entries {
		require.False(t, strings.HasSuffix(e.Name(), ".tmp"), "temporary file %s left in %s", e.Name(), dir)
	}
}

// TestLinkStagedCountsTheDestination: the body staged for the destination account counts
// against the staging limit once, however often it is staged, and removing both files
// returns the count to where it was (issue #1174).
func TestLinkStagedCountsTheDestination(t *testing.T) {
	for _, tc := range []struct {
		name   string
		noLink bool
	}{{"hard link", false}, {"copy", true}} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.noLink {
				refuseHardLinks(t)
			}
			w := &UploadWorker{path: t.TempDir(), maxStagingSize: 1 << 20}
			atomic.StoreInt64(&w.currentStagingSize, 600) // other bodies staged
			hash := stagingHash("a")
			body := bytes.Repeat([]byte("x"), 300)
			_, err := w.StoreLocally(hash, 1, body)
			require.NoError(t, err)

			for range 2 {
				require.NoError(t, w.LinkStaged(hash, 1, 2))
			}
			require.Equal(t, int64(1200), atomic.LoadInt64(&w.currentStagingSize),
				"the destination's staging of the 300 byte body must be counted once")

			dst := w.FilePath(hash, 2)
			got, err := os.ReadFile(dst)
			require.NoError(t, err)
			require.Equal(t, body, got)
			srcInfo, err := os.Stat(w.FilePath(hash, 1))
			require.NoError(t, err)
			dstInfo, err := os.Stat(dst)
			require.NoError(t, err)
			require.Equal(t, !tc.noLink, os.SameFile(srcInfo, dstInfo))
			requireNoTemporaryFiles(t, filepath.Dir(dst))

			for _, accountID := range []int64{1, 2} {
				require.NoError(t, w.RemoveLocalFile(w.FilePath(hash, accountID)))
			}
			require.Equal(t, int64(600), atomic.LoadInt64(&w.currentStagingSize),
				"removing both stagings of the body must leave the count where it started")
		})
	}
}

// TestLinkStagedSourceNotStaged: a body that is not staged here stages nothing and
// changes nothing, and says so with fs.ErrNotExist, which a cross-account COPY or MOVE
// takes as "copy it in S3 instead".
func TestLinkStagedSourceNotStaged(t *testing.T) {
	for _, tc := range []struct {
		name   string
		noLink bool
	}{{"hard link", false}, {"copy", true}} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.noLink {
				refuseHardLinks(t)
			}
			w := &UploadWorker{path: t.TempDir()}
			hash := stagingHash("b")

			err := w.LinkStaged(hash, 1, 2)
			require.ErrorIs(t, err, fs.ErrNotExist)
			require.Zero(t, atomic.LoadInt64(&w.currentStagingSize))
			_, statErr := os.Stat(w.FilePath(hash, 2))
			require.True(t, os.IsNotExist(statErr), "nothing may be staged for the destination, got %v", statErr)
			requireNoTemporaryFiles(t, filepath.Dir(w.FilePath(hash, 2)))
		})
	}
}

// TestLinkStagedConcurrentWithStoreLocally: the destination account stages the same
// body itself (an APPEND by the owner) while it is linked to it. The path's one file is
// counted once, whichever lands first.
func TestLinkStagedConcurrentWithStoreLocally(t *testing.T) {
	for _, tc := range []struct {
		name   string
		noLink bool
	}{{"hard link", false}, {"copy", true}} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.noLink {
				refuseHardLinks(t)
			}
			w := &UploadWorker{path: t.TempDir()}
			body := bytes.Repeat([]byte("concurrent cross-account body\r\n"), 1024)
			size := int64(len(body))

			for round := range 20 {
				hash := fmt.Sprintf("%064x", round+1)
				_, err := w.StoreLocally(hash, 1, body)
				require.NoError(t, err)

				var wg sync.WaitGroup
				errs := make(chan error, 8)
				for i := range 8 {
					wg.Add(1)
					go func() {
						defer wg.Done()
						if i%2 == 0 {
							errs <- w.LinkStaged(hash, 1, 2)
						} else {
							_, err := w.StoreLocally(hash, 2, body)
							errs <- err
						}
					}()
				}
				wg.Wait()
				close(errs)
				for err := range errs {
					require.NoError(t, err)
				}
				require.Equal(t, 2*size, atomic.LoadInt64(&w.currentStagingSize), "round %d", round)

				for _, accountID := range []int64{1, 2} {
					require.NoError(t, w.RemoveLocalFile(w.FilePath(hash, accountID)))
				}
				require.Zero(t, atomic.LoadInt64(&w.currentStagingSize), "round %d", round)
			}
		})
	}
}

// TestLinkStagedOrStore: a delivery into a shared mailbox another account owns stages
// the body for the owner by linking the recipient's file, and from the bytes it holds
// when that file is gone (the recipient's upload removed it), counting it once either
// way (issue #1192).
func TestLinkStagedOrStore(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 300)
	for _, tc := range []struct {
		name      string
		srcStaged bool
	}{{"source staged", true}, {"source gone", false}} {
		t.Run(tc.name, func(t *testing.T) {
			w := &UploadWorker{path: t.TempDir(), maxStagingSize: 1 << 20}
			hash := stagingHash("c")
			var want int64 = 300
			if tc.srcStaged {
				_, err := w.StoreLocally(hash, 1, body)
				require.NoError(t, err)
				want = 600
			}

			require.NoError(t, w.LinkStagedOrStore(hash, 1, 2, body))

			dst := w.FilePath(hash, 2)
			got, err := os.ReadFile(dst)
			require.NoError(t, err)
			require.Equal(t, body, got)
			if tc.srcStaged {
				srcInfo, err := os.Stat(w.FilePath(hash, 1))
				require.NoError(t, err)
				dstInfo, err := os.Stat(dst)
				require.NoError(t, err)
				require.True(t, os.SameFile(srcInfo, dstInfo), "a staged source must be linked, not written again")
			}
			require.Equal(t, want, atomic.LoadInt64(&w.currentStagingSize))
			requireNoTemporaryFiles(t, filepath.Dir(dst))
		})
	}
}

// TestLinkStagedOutlivesTheOrphanSweep: the caller of LinkStaged inserts the destination's
// pending row only after it returns, so until that commits the destination's staging file
// is one the orphan sweep finds no row for. A hard link keeps the source inode's mtime
// (an hour old for a body whose upload is stuck), and a destination already staged can be
// an orphan an hour old; either way the grace period had already run out, and a sweep
// in that window removed the file, leaving the owner's message with no body to upload.
func TestLinkStagedOutlivesTheOrphanSweep(t *testing.T) {
	old := time.Now().Add(-2 * time.Hour)
	for _, tc := range []struct {
		name      string
		dstStaged bool // an orphan staged for the destination before the link
	}{{"linked old source", false}, {"destination already staged", true}} {
		t.Run(tc.name, func(t *testing.T) {
			mockDB := new(mockUploaderDB)
			w := &UploadWorker{rdb: mockDB, path: t.TempDir(), maxStagingSize: 1 << 20}
			hash := stagingHash("d")
			body := bytes.Repeat([]byte("y"), 300)

			_, err := w.StoreLocally(hash, 1, body)
			require.NoError(t, err)
			mockDB.setPendingUpload(1, hash) // the source's upload is still queued
			if tc.dstStaged {
				_, err := w.StoreLocally(hash, 2, body)
				require.NoError(t, err)
			}
			for _, accountID := range []int64{1, 2} {
				if p := w.FilePath(hash, accountID); fileSize(p) > 0 {
					require.NoError(t, os.Chtimes(p, old, old))
				}
			}

			require.NoError(t, w.LinkStaged(hash, 1, 2))
			// The destination's insert has not committed: the sweep sees no row for it.
			require.NoError(t, w.cleanupOrphanedFiles(context.Background()))

			got, err := os.ReadFile(w.FilePath(hash, 2))
			require.NoError(t, err, "the destination's file must outlive a sweep that runs before its pending row commits")
			require.Equal(t, body, got)
		})
	}
}
