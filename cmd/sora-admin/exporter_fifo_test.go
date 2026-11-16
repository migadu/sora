//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// An export merges into what its destination already holds (dovecot-keywords,
// dovecot-uidlist and the cur/ and new/ directories it names files in), so it may be
// given a maildir its owner could write to. The owner can leave a FIFO at any of those
// names, and opening a FIFO for reading blocks until something opens it for writing:
// the export never finished (#1630). This is the export's side of #1608.

// returnsDespiteFIFO makes path a FIFO, runs call and fails the test unless call
// returns within a few seconds; it returns call's error.
func returnsDespiteFIFO(t *testing.T, path string, call func() error) error {
	t.Helper()
	require.NoError(t, unix.Mkfifo(path, 0o644))
	done := make(chan error, 1)
	go func() { done <- call() }()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatalf("the export blocked on the FIFO at %s", path)
		return nil
	}
}

func TestExportDoesNotBlockOnFIFODovecotKeywords(t *testing.T) {
	exporter, dest := newLinkTestExporter(t, nil, ExporterOptions{Dovecot: true})
	keywords := filepath.Join(dest, "dovecot-keywords")

	err := returnsDespiteFIFO(t, keywords, func() error {
		return exporter.prepareKeywords("INBOX", []db.Message{{UID: 1, CustomFlags: []string{"$Work"}}})
	})

	// A FIFO names no keywords to keep: it is replaced like a file that cannot be read.
	require.NoError(t, err)
	assertRegularFile(t, keywords)
	got, err := os.ReadFile(keywords)
	require.NoError(t, err)
	assert.Equal(t, "0 $Work\n", string(got))
}

// A regular dovecot-keywords an earlier run left is still read: the numbering it gives
// is kept, so files that run wrote keep their meaning.
func TestExportKeepsExistingDovecotKeywordsNumbering(t *testing.T) {
	exporter, dest := newLinkTestExporter(t, nil, ExporterOptions{Dovecot: true})
	keywords := filepath.Join(dest, "dovecot-keywords")
	require.NoError(t, os.WriteFile(keywords, []byte("3 $Old\n"), 0o644))

	require.NoError(t, exporter.prepareKeywords("INBOX", []db.Message{{UID: 1, CustomFlags: []string{"$Old", "$Work"}}}))

	got, err := os.ReadFile(keywords)
	require.NoError(t, err)
	assert.Equal(t, "0 $Work\n3 $Old\n", string(got))
}

func TestExportDoesNotBlockOnFIFODovecotUIDList(t *testing.T) {
	exporter, dest := newLinkTestExporter(t, nil, ExporterOptions{ExportUIDList: true})
	uidlist := filepath.Join(dest, "dovecot-uidlist")
	exporter.uidMappings["INBOX"] = []UIDFileMapping{{UID: 7, Filename: "1700000001.M1P1.host"}}

	err := returnsDespiteFIFO(t, uidlist, func() error {
		return exporter.generateDovecotUIDLists([]*db.DBMailbox{{Name: "INBOX", UIDValidity: 42}})
	})

	// A FIFO names no UIDs to keep: it is replaced like a file that cannot be read.
	require.NoError(t, err)
	assertRegularFile(t, uidlist)
	written, err := ParseDovecotUIDList(dest)
	require.NoError(t, err)
	require.NotNil(t, written)
	assert.Equal(t, uint32(42), written.UIDValidity)
	assert.Equal(t, map[string]uint32{"1700000001.M1P1.host": 7}, written.UIDMappings)
}

// The merge with an earlier run's dovecot-uidlist lists cur/ and new/ to keep the
// entries whose file is still there. The owner can replace either directory with a FIFO
// once the export has created it, at any time before the uidlist is written at the end.
func TestExportDoesNotBlockOnFIFOMaildirDirectory(t *testing.T) {
	for _, sub := range []string{"cur", "new"} {
		t.Run(sub, func(t *testing.T) {
			exporter, dest := newLinkTestExporter(t, nil, ExporterOptions{ExportUIDList: true})
			other := map[string]string{"cur": "new", "new": "cur"}[sub]
			require.NoError(t, os.WriteFile(filepath.Join(dest, other, "1600000000.M1P1.host"), []byte(linkTestMessageBody), 0o644))
			require.NoError(t, os.WriteFile(filepath.Join(dest, "dovecot-uidlist"), []byte("3 V42 N4\n3 :1600000000.M1P1.host\n"), 0o644))
			require.NoError(t, os.Remove(filepath.Join(dest, sub)))
			exporter.uidMappings["INBOX"] = []UIDFileMapping{{UID: 7, Filename: "1700000001.M1P1.host"}}

			err := returnsDespiteFIFO(t, filepath.Join(dest, sub), func() error {
				return exporter.generateDovecotUIDLists([]*db.DBMailbox{{Name: "INBOX", UIDValidity: 42}})
			})

			// The FIFO holds no message files; the earlier entry whose file is in the
			// other directory is kept.
			require.NoError(t, err)
			written, err := ParseDovecotUIDList(dest)
			require.NoError(t, err)
			require.NotNil(t, written)
			assert.Equal(t, map[string]uint32{"1600000000.M1P1.host": 3, "1700000001.M1P1.host": 7}, written.UIDMappings)
		})
	}
}

func fileStatusFlags(t *testing.T, f *os.File) int {
	t.Helper()
	conn, err := f.SyscallConn()
	require.NoError(t, err)
	var flags int
	var fcntlErr error
	require.NoError(t, conn.Control(func(fd uintptr) {
		flags, fcntlErr = unix.FcntlInt(fd, unix.F_GETFL, 0)
	}))
	require.NoError(t, fcntlErr)
	return flags
}

// openExportEntry opens regular files with O_NONBLOCK so a FIFO does not block, and must
// clear O_NONBLOCK before returning: Go does not register regular files with the runtime
// poller, so a filesystem that honours O_NONBLOCK for regular files would otherwise fail
// reads with EAGAIN (silently discarding existing dovecot-keywords and dovecot-uidlist
// state). Directories must likewise be returned without O_NONBLOCK set.
func TestOpenExportEntryReadsInBlockingMode(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dovecot-keywords"), []byte("0 $Work\n"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "cur"), 0o755))
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	defer root.Close()

	t.Run("regular file", func(t *testing.T) {
		f, err := openExportEntry(root, "dovecot-keywords", false)
		require.NoError(t, err)
		defer f.Close()
		assert.Zero(t, fileStatusFlags(t, f)&unix.O_NONBLOCK, "a regular export file was left in non-blocking mode")
	})

	t.Run("directory", func(t *testing.T) {
		for _, name := range []string{"cur", "."} {
			d, err := openExportEntry(root, name, true)
			require.NoError(t, err)
			flags := fileStatusFlags(t, d)
			require.NoError(t, d.Close())
			assert.Zero(t, flags&unix.O_NONBLOCK, "export directory %q was left in non-blocking mode", name)
		}
	})
}

// Opening a directory entry with dir == true must pass O_DIRECTORY so the kernel rejects
// any non-directory (regular file, FIFO, or device node) with ENOTDIR before opening it.
func TestOpenExportEntryRejectsNonDirectoryWithoutOpening(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "regular"), []byte("x"), 0o644))
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	defer root.Close()

	t.Run("regular file", func(t *testing.T) {
		f, err := openExportEntry(root, "regular", true)
		if f != nil {
			f.Close()
		}
		require.Error(t, err)
		assert.False(t, os.IsNotExist(err))
		assert.ErrorIs(t, err, unix.ENOTDIR)
		assert.Contains(t, err.Error(), "refusing regular in the export directory: it is not a directory")
	})

	t.Run("FIFO", func(t *testing.T) {
		fifoPath := filepath.Join(dir, "cur")
		err := returnsDespiteFIFO(t, fifoPath, func() error {
			f, err := openExportEntry(root, "cur", true)
			if f != nil {
				f.Close()
			}
			return err
		})
		require.Error(t, err)
		assert.False(t, os.IsNotExist(err))
		assert.ErrorIs(t, err, unix.ENOTDIR)
		assert.Contains(t, err.Error(), "refusing cur in the export directory: it is not a directory")
	})

	t.Run("link to FIFO within export directory", func(t *testing.T) {
		targetFIFO := filepath.Join(dir, "tmp-fifo")
		require.NoError(t, os.Symlink("tmp-fifo", filepath.Join(dir, "new")))
		err := returnsDespiteFIFO(t, targetFIFO, func() error {
			f, err := openExportEntry(root, "new", true)
			if f != nil {
				f.Close()
			}
			return err
		})
		require.Error(t, err)
		assert.False(t, os.IsNotExist(err))
		assert.ErrorIs(t, err, unix.ENOTDIR)
		assert.Contains(t, err.Error(), "refusing new in the export directory: it is not a directory")
	})
}
