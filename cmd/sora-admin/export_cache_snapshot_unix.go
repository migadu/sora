//go:build darwin || linux

package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// SQLite's default Unix VFS uses these main-file POSIX lock bytes (os.h and
// os_unix.c). Cover pending+reserved+the whole510-byte shared range in one
// nonblocking request. WAL connections keep a SHARED main-file lock even outside
// transactions: sqlite.org/walformat.html#how_the_various_locks_are_used.
const sqliteLockStart = 0x40000000
const sqliteLockLength = 512

// exportSnapshotDirFD is, in the helper, the descriptor of the directory that holds
// the cache: openExportCacheForDryRun passes the root the dry run checked as the
// helper's first extra file, and every source file is opened and checked through it.
const exportSnapshotDirFD = 3

func copyExportCacheSnapshot(req exportSnapshotRequest) error {
	root := exportSnapshotDirFD
	var st unix.Stat_t
	if err := unix.Fstat(root, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("the cache directory was not passed to the snapshot helper")
	}
	name := maildirCacheName
	// O_RDWR is needed for F_WRLCK, but no source descriptor is ever written.
	f, err := openExportSnapshotSource(root, name, unix.O_RDWR)
	if err != nil {
		return fmt.Errorf("open cache for exclusive snapshot lock: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if err := requireSingleLinkExportCache(info); err != nil {
		return fmt.Errorf("unsafe cache: %w", err)
	}
	if err := requireExportSnapshotFilesystem(f); err != nil {
		return err
	}
	lock := unix.Flock_t{Type: unix.F_WRLCK, Whence: int16(io.SeekStart), Start: sqliteLockStart, Len: sqliteLockLength}
	if err := unix.FcntlFlock(f.Fd(), unix.F_SETLK, &lock); err != nil {
		return fmt.Errorf("cache is active or cannot be exclusively locked; stop import/export users before preview: %w", err)
	}
	// No SQLite connection exists in this process. Keep this sole descriptor open
	// until all raw copies and identity checks finish; closing it releases the lock.
	if err := verifyExportSnapshotSource(root, name, info); err != nil {
		return err
	}
	if _, err := lstatAt(root, name+"-journal"); !os.IsNotExist(err) {
		return fmt.Errorf("cache has a rollback journal or cannot inspect it; recover/close it before preview: %v", err)
	}
	destination, err := os.OpenRoot(req.Destination)
	if err != nil {
		return err
	}
	defer destination.Close()
	if err := copyExportSnapshotFile(destination, name, f); err != nil {
		return err
	}
	var walInfo os.FileInfo
	wal, err := openExportSnapshotSource(root, name+"-wal", unix.O_RDONLY)
	if err == nil {
		defer wal.Close()
		walInfo, err = wal.Stat()
		if err != nil {
			return err
		}
		if err := requireSingleLinkExportCache(walInfo); err != nil {
			return fmt.Errorf("unsafe cache WAL: %w", err)
		}
		if err := copyExportSnapshotFile(destination, name+"-wal", wal); err != nil {
			return err
		}
		if err := verifyExportSnapshotSource(root, name+"-wal", walInfo); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("open cache WAL: %w", err)
	}
	if walInfo == nil {
		if _, err := lstatAt(root, name+"-wal"); !os.IsNotExist(err) {
			return fmt.Errorf("cache WAL appeared during snapshot")
		}
	}
	if err := verifyExportSnapshotSource(root, name, info); err != nil {
		return err
	}
	if _, err := lstatAt(root, name+"-journal"); !os.IsNotExist(err) {
		return fmt.Errorf("cache journal appeared during snapshot")
	}
	return nil
}

// openExportSnapshotSource opens name in the directory root with flag, never
// following a link at the name, and with O_NONBLOCK, so that a FIFO there does not
// wait for a writer.
func openExportSnapshotSource(root int, name string, flag int) (*os.File, error) {
	var fd int
	err := ignoringEINTR(func() (err error) {
		fd, err = unix.Openat(root, name, flag|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		return err
	})
	if err != nil {
		return nil, &fs.PathError{Op: "openat", Path: name, Err: err}
	}
	return os.NewFile(uintptr(fd), name), nil
}

func verifyExportSnapshotSource(root int, name string, before os.FileInfo) error {
	after, err := lstatAt(root, name)
	if err != nil {
		return &fs.PathError{Op: "lstat", Path: name, Err: err}
	}
	if !after.Mode().IsRegular() || !sameFileID(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return fmt.Errorf("cache component changed during snapshot: %s", name)
	}
	return nil
}

func copyExportSnapshotFile(destination *os.Root, name string, source *os.File) error {
	f, err := destination.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, source)
	closeErr := f.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}

// Multiple names for a DB can give it distinct WAL/journal names. Locking its
// inode cannot tell which alias owns crash-recovery state, so refuse that case.
func requireSingleLinkExportCache(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Nlink != 1 {
		return fmt.Errorf("must have exactly one hard link")
	}
	return nil
}
