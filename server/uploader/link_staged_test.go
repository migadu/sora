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

// TestLinkStagedHardLinkSurvivesOrphanSweepBeforeCommit: os.Link shares the source
// inode and its st_mtime, so linking a body that has been queued longer than
// cleanupGracePeriod (kept on disk by srcAccountID's pending_uploads row) must refresh
// ModTime under dst's staging lock; otherwise cleanupOrphanedFiles deletes dst before
// destAccountID's transaction commits its pending_uploads row.
func TestLinkStagedHardLinkSurvivesOrphanSweepBeforeCommit(t *testing.T) {
	const srcAccountID, destAccountID = int64(1), int64(2)
	hash := stagingHash("d")
	body := bytes.Repeat([]byte("queued during outage\r\n"), 64)
	bodySize := int64(len(body))

	rdb := &mockDB{
		ExistingPendingUploadsFunc: func(ctx context.Context, accountID int64, hashes []string) (map[string]struct{}, error) {
			if accountID == srcAccountID {
				return map[string]struct{}{hash: {}}, nil
			}
			// destAccountID's InsertMessage / pending_uploads transaction is still in flight.
			return map[string]struct{}{}, nil
		},
	}
	w := &UploadWorker{
		rdb:                rdb,
		path:               t.TempDir(),
		cleanupGracePeriod: time.Hour,
	}

	srcPath, err := w.StoreLocally(hash, srcAccountID, body)
	require.NoError(t, err)
	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(*srcPath, old, old))

	require.NoError(t, w.LinkStaged(hash, srcAccountID, destAccountID))
	require.Equal(t, 2*bodySize, atomic.LoadInt64(&w.currentStagingSize))

	require.NoError(t, w.cleanupOrphanedFiles(context.Background()))

	dst := w.FilePath(hash, destAccountID)
	got, err := os.ReadFile(dst)
	require.NoError(t, err, "freshly linked destination body must survive orphan sweep while its pending_uploads commit is in flight")
	require.Equal(t, body, got)
	dstInfo, err := os.Stat(dst)
	require.NoError(t, err)
	require.True(t, dstInfo.ModTime().After(time.Now().Add(-time.Minute)),
		"LinkStaged must refresh ModTime into the grace window, got %v", dstInfo.ModTime())
	require.Equal(t, 2*bodySize, atomic.LoadInt64(&w.currentStagingSize))
}

// TestLinkStagedRefreshesExistingDestinationModTime: adopting a right-sized file
// already at dst (an earlier uncommitted leftover) must refresh its ModTime under
// pathMu without double-counting its bytes, so neither a subsequent nor an in-flight
// cleanupOrphanedFiles sweep deletes dst before destAccountID's row commits.
func TestLinkStagedRefreshesExistingDestinationModTime(t *testing.T) {
	const srcAccountID, destAccountID = int64(1), int64(2)
	body := bytes.Repeat([]byte("pre-existing destination body\r\n"), 64)
	bodySize := int64(len(body))

	t.Run("sweep after LinkStaged", func(t *testing.T) {
		hash := stagingHash("e")
		rdb := &mockDB{
			ExistingPendingUploadsFunc: func(ctx context.Context, accountID int64, hashes []string) (map[string]struct{}, error) {
				if accountID == srcAccountID {
					return map[string]struct{}{hash: {}}, nil
				}
				return map[string]struct{}{}, nil
			},
		}
		w := &UploadWorker{
			rdb:                rdb,
			path:               t.TempDir(),
			cleanupGracePeriod: time.Hour,
		}

		_, err := w.StoreLocally(hash, srcAccountID, body)
		require.NoError(t, err)
		dstPath, err := w.StoreLocally(hash, destAccountID, body)
		require.NoError(t, err)
		old := time.Now().Add(-2 * time.Hour)
		require.NoError(t, os.Chtimes(*dstPath, old, old))
		require.Equal(t, 2*bodySize, atomic.LoadInt64(&w.currentStagingSize))

		require.NoError(t, w.LinkStaged(hash, srcAccountID, destAccountID))
		require.Equal(t, 2*bodySize, atomic.LoadInt64(&w.currentStagingSize),
			"reusing a right-sized destination file must not recount its bytes")

		require.NoError(t, w.cleanupOrphanedFiles(context.Background()))

		got, err := os.ReadFile(*dstPath)
		require.NoError(t, err, "adopted destination file must survive orphan sweep after mtime refresh")
		require.Equal(t, body, got)
		require.Equal(t, 2*bodySize, atomic.LoadInt64(&w.currentStagingSize))
	})

	t.Run("in-flight sweep races with LinkStaged", func(t *testing.T) {
		hash := stagingHash("f")
		var w *UploadWorker
		linked := false
		rdb := &mockDB{
			ExistingPendingUploadsFunc: func(ctx context.Context, accountID int64, hashes []string) (map[string]struct{}, error) {
				if accountID == srcAccountID {
					return map[string]struct{}{hash: {}}, nil
				}
				require.NoError(t, w.LinkStaged(hash, srcAccountID, destAccountID))
				linked = true
				return map[string]struct{}{}, nil
			},
		}
		w = &UploadWorker{
			rdb:                rdb,
			path:               t.TempDir(),
			cleanupGracePeriod: time.Hour,
		}

		_, err := w.StoreLocally(hash, srcAccountID, body)
		require.NoError(t, err)
		dstPath, err := w.StoreLocally(hash, destAccountID, body)
		require.NoError(t, err)
		old := time.Now().Add(-2 * time.Hour)
		require.NoError(t, os.Chtimes(*dstPath, old, old))

		require.NoError(t, w.cleanupOrphanedFiles(context.Background()))
		require.True(t, linked)

		got, err := os.ReadFile(*dstPath)
		require.NoError(t, err, "in-flight orphan sweep must see refreshed ModTime under pathMu and keep dst")
		require.Equal(t, body, got)
		require.Equal(t, 2*bodySize, atomic.LoadInt64(&w.currentStagingSize))
	})
}

// TestLinkStagedReplacesTruncatedExistingDestination: a wrong-sized leftover at dst
// must not be adopted on fs.ErrExist; LinkStaged must atomically replace it with src's
// full body and adjust currentStagingSize from oldSize to newSize.
func TestLinkStagedReplacesTruncatedExistingDestination(t *testing.T) {
	const srcAccountID, destAccountID = int64(1), int64(2)
	body := bytes.Repeat([]byte("complete cross-account message body\r\n"), 64)
	bodySize := int64(len(body))
	truncated := body[:37]
	truncatedSize := int64(len(truncated))

	for idx, tc := range []struct {
		name   string
		noLink bool
	}{{"hard link", false}, {"copy", true}} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.noLink {
				refuseHardLinks(t)
			}
			hash := fmt.Sprintf("%064x", 0x100+idx)
			rdb := &mockDB{
				ExistingPendingUploadsFunc: func(ctx context.Context, accountID int64, hashes []string) (map[string]struct{}, error) {
					if accountID == srcAccountID {
						return map[string]struct{}{hash: {}}, nil
					}
					return map[string]struct{}{}, nil
				},
			}
			w := &UploadWorker{
				rdb:                rdb,
				path:               t.TempDir(),
				cleanupGracePeriod: time.Hour,
			}

			_, err := w.StoreLocally(hash, srcAccountID, body)
			require.NoError(t, err)
			dstPath, err := w.StoreLocally(hash, destAccountID, truncated)
			require.NoError(t, err)
			old := time.Now().Add(-2 * time.Hour)
			require.NoError(t, os.Chtimes(*dstPath, old, old))
			require.Equal(t, bodySize+truncatedSize, atomic.LoadInt64(&w.currentStagingSize))

			require.NoError(t, w.LinkStaged(hash, srcAccountID, destAccountID))

			got, err := os.ReadFile(*dstPath)
			require.NoError(t, err)
			require.Equal(t, body, got, "truncated destination file must be replaced with full source body")
			require.Equal(t, 2*bodySize, atomic.LoadInt64(&w.currentStagingSize),
				"currentStagingSize must replace truncated size (%d) with full size (%d)", truncatedSize, bodySize)
			requireNoTemporaryFiles(t, filepath.Dir(*dstPath))

			require.NoError(t, w.cleanupOrphanedFiles(context.Background()))
			got, err = os.ReadFile(*dstPath)
			require.NoError(t, err, "replaced destination file must survive orphan sweep")
			require.Equal(t, body, got)

			for _, accountID := range []int64{srcAccountID, destAccountID} {
				require.NoError(t, w.RemoveLocalFile(w.FilePath(hash, accountID)))
			}
			require.Zero(t, atomic.LoadInt64(&w.currentStagingSize))
		})
	}
}
