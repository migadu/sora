//go:build darwin || linux

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// SQLite's default Unix VFS uses these main-file POSIX lock bytes (os.h and
// os_unix.c). Cover pending+reserved+the whole510-byte shared range in one
// nonblocking request. WAL connections keep a SHARED main-file lock even outside
// transactions: sqlite.org/walformat.html#how_the_various_locks_are_used.
const sqliteLockStart = 0x40000000
const sqliteLockLength = 512

func copyExportCacheSnapshot(req exportSnapshotRequest) error {
	dir, err := resolveMaildirDir(filepath.Dir(req.Source))
	if err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	name := filepath.Base(req.Source)
	if name != maildirCacheName {
		return fmt.Errorf("unexpected cache filename")
	}
	// O_RDWR is needed for F_WRLCK, but no source descriptor is ever written.
	f, err := root.OpenFile(name, os.O_RDWR|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
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
	if _, err := root.Lstat(name + "-journal"); !os.IsNotExist(err) {
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
	wal, err := root.OpenFile(name+"-wal", os.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW, 0)
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
		if _, err := root.Lstat(name + "-wal"); !os.IsNotExist(err) {
			return fmt.Errorf("cache WAL appeared during snapshot")
		}
	}
	if err := verifyExportSnapshotSource(root, name, info); err != nil {
		return err
	}
	if _, err := root.Lstat(name + "-journal"); !os.IsNotExist(err) {
		return fmt.Errorf("cache journal appeared during snapshot")
	}
	return nil
}

func verifyExportSnapshotSource(root *os.Root, name string, before os.FileInfo) error {
	after, err := root.Lstat(name)
	if err != nil {
		return err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
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
