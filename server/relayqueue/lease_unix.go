//go:build unix

package relayqueue

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// A lease is held through delivery, not just the claim's renames. flock is released
// by process death. No PID, age or wall-clock observation establishes ownership.
type queueLease struct {
	file *os.File
	path string
}

func (q *DiskQueue) tryLease(id string) (*queueLease, error) {
	if id == "" || id == "." || id == ".." || filepath.Base(id) != id {
		return nil, fmt.Errorf("invalid relay message id %q", id)
	}
	path := filepath.Join(q.processingDir, ".lease-"+id)
	for {
		f, err := q.openLeaseFile(path)
		if err != nil {
			return nil, err
		}
		fd := int(f.Fd())
		info, err := f.Stat()
		if err == nil && !info.Mode().IsRegular() {
			err = fmt.Errorf("relay lease is not a regular file")
		}
		if err == nil && info.Mode().Perm() != 0600 {
			err = fmt.Errorf("relay lease must have mode 0600")
		}
		if err == nil {
			directory, statErr := os.Stat(q.processingDir)
			if statErr != nil {
				err = statErr
			} else {
				fileOwner, fileOK := info.Sys().(*syscall.Stat_t)
				dirOwner, dirOK := directory.Sys().(*syscall.Stat_t)
				if !fileOK || !dirOK {
					err = fmt.Errorf("cannot determine relay lease ownership")
				} else if fileOwner.Uid != dirOwner.Uid {
					err = fmt.Errorf("relay lease owner differs from processing directory")
				}
			}
		}
		if err != nil {
			f.Close()
			return nil, err
		}

		if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
			f.Close()
			if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
				return nil, nil
			}
			return nil, err
		}
		current, statErr := os.Lstat(path)
		if statErr == nil && os.SameFile(info, current) {
			return &queueLease{f, path}, nil
		}
		// A previous holder may have removed the name after we opened it. Never use
		// that detached inode while another process can own the replacement name.
		unix.Flock(fd, unix.LOCK_UN)
		f.Close()
		if statErr != nil && !os.IsNotExist(statErr) {
			return nil, statErr
		}
	}
}

func (l *queueLease) close() {
	if l == nil {
		return
	}
	if current, err := os.Lstat(l.path); err == nil {
		if own, err := l.file.Stat(); err == nil && os.SameFile(own, current) {
			_ = os.Remove(l.path)
		}
	}
	_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	_ = l.file.Close()
}

// Hand ownership over only on a private new inode, before its lease name appears.
// Opening/chowning an existing path could give away a hard-linked unrelated file
// when sora-admin runs as root in the server-owned spool.
func (q *DiskQueue) openLeaseFile(path string) (*os.File, error) {
	for {
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err == nil {
			return os.NewFile(uintptr(fd), path), nil
		}
		if !errors.Is(err, unix.ENOENT) {
			return nil, err
		}
		f, err := os.CreateTemp(q.processingDir, tempFilePrefix+"lease-")
		if err != nil {
			return nil, err
		}
		name := f.Name()
		err = f.Chmod(0600)
		if err == nil {
			owner, ownerErr := foreignOwner(q.processingDir)
			err = ownerErr
			if err == nil && owner != nil {
				err = f.Chown(owner.uid, owner.gid)
			}
		}
		if err == nil {
			err = os.Link(name, path)
		}
		_ = os.Remove(name)
		if err == nil {
			return f, nil
		}
		f.Close()
		if !os.IsExist(err) {
			return nil, err
		}
		// An existing lease is opened unchanged. The post-flock inode check also
		// rejects a replaced temporary name or a concurrently retired lease inode.
	}
}
