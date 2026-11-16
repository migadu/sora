package main

import (
	"io/fs"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// openSearchDir opens the directory name in the directory dirfd (unix.AT_FDCWD for an
// absolute name) without following a symbolic link, for search only where the system
// has such an open (searchDirFlags): the descriptor can name the entries below it, as
// a path does, and needs only search permission, not read permission. A system that
// refuses the flag for a directory gets an open for reading, which needs both.
func openSearchDir(dirfd int, name string) (int, error) {
	const flags = unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	var fd int
	err := ignoringEINTR(func() (err error) {
		fd, err = unix.Openat(dirfd, name, searchDirFlags|flags, 0)
		return err
	})
	if searchDirFlags != unix.O_RDONLY && (err == unix.EINVAL || err == unix.EISDIR || err == unix.EOPNOTSUPP) {
		err = ignoringEINTR(func() (err error) {
			fd, err = unix.Openat(dirfd, name, unix.O_RDONLY|flags, 0)
			return err
		})
	}
	return fd, err
}

// lstatAt is os.Lstat of name in the directory dirfd.
func lstatAt(dirfd int, name string) (*statInfo, error) {
	info := &statInfo{name: name}
	err := ignoringEINTR(func() error { return unix.Fstatat(dirfd, name, &info.st, unix.AT_SYMLINK_NOFOLLOW) })
	if err != nil {
		return nil, err
	}
	return info, nil
}

// fstatDir is os.Stat of the directory open as fd, which is named name.
func fstatDir(fd int, name string) (*statInfo, error) {
	info := &statInfo{name: name}
	if err := ignoringEINTR(func() error { return unix.Fstat(fd, &info.st) }); err != nil {
		return nil, err
	}
	return info, nil
}

// readlinkAt is os.Readlink of name in the directory dirfd.
func readlinkAt(dirfd int, name string) (string, error) {
	for size := 256; ; size *= 2 {
		buf := make([]byte, size)
		var n int
		err := ignoringEINTR(func() (err error) {
			n, err = unix.Readlinkat(dirfd, name, buf)
			return err
		})
		if err != nil {
			return "", err
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
}

func ignoringEINTR(fn func() error) error {
	for {
		if err := fn(); err != unix.EINTR {
			return err
		}
	}
}

// statInfo is the fs.FileInfo of a stat made by descriptor; Sys is its *unix.Stat_t.
type statInfo struct {
	name string
	st   unix.Stat_t
}

func (s *statInfo) Name() string       { return s.name }
func (s *statInfo) Size() int64        { return s.st.Size }
func (s *statInfo) ModTime() time.Time { return time.Unix(s.st.Mtim.Unix()) }
func (s *statInfo) IsDir() bool        { return s.Mode().IsDir() }
func (s *statInfo) Sys() any           { return &s.st }

func (s *statInfo) Mode() fs.FileMode {
	mode := fs.FileMode(s.st.Mode & 0o777)
	switch uint32(s.st.Mode) & unix.S_IFMT {
	case unix.S_IFREG:
	case unix.S_IFDIR:
		mode |= fs.ModeDir
	case unix.S_IFLNK:
		mode |= fs.ModeSymlink
	case unix.S_IFIFO:
		mode |= fs.ModeNamedPipe
	case unix.S_IFSOCK:
		mode |= fs.ModeSocket
	case unix.S_IFCHR:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case unix.S_IFBLK:
		mode |= fs.ModeDevice
	default:
		mode |= fs.ModeIrregular
	}
	if s.st.Mode&unix.S_ISUID != 0 {
		mode |= fs.ModeSetuid
	}
	if s.st.Mode&unix.S_ISGID != 0 {
		mode |= fs.ModeSetgid
	}
	if s.st.Mode&unix.S_ISVTX != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}

// sameStat reports whether a and b describe the same file.
func sameStat(a, b *statInfo) bool {
	return a.st.Dev == b.st.Dev && a.st.Ino == b.st.Ino
}

// sameFileID reports whether a and b describe the same file, whether each comes from
// the os package or from a stat made by descriptor (statInfo).
func sameFileID(a, b fs.FileInfo) bool {
	aDev, aIno, aOK := fileID(a)
	bDev, bIno, bOK := fileID(b)
	return aOK && bOK && aDev == bDev && aIno == bIno
}

// fileID returns the device and inode number of the file info describes.
func fileID(info fs.FileInfo) (dev, ino uint64, ok bool) {
	switch st := info.Sys().(type) {
	case *unix.Stat_t:
		return uint64(st.Dev), uint64(st.Ino), true
	case *syscall.Stat_t:
		return uint64(st.Dev), uint64(st.Ino), true
	}
	return 0, 0, false
}
