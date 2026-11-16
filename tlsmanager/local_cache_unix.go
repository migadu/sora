//go:build unix

package tlsmanager

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func lockLocalEntry(ctx context.Context, parent *os.Root, name string) (func(), error) {
	lockName := localPrivatePrefix + "lock-" + localDataFingerprint([]byte(name))
	for {
		f, err := openLocalLease(parent, lockName)
		if err != nil {
			return nil, err
		}
		fail := func(err error) (func(), error) { f.Close(); return nil, err }
		info, err := f.Stat()
		if err != nil {
			return fail(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return fail(fmt.Errorf("certificate lease must be a regular mode-0600 file"))
		}
		dir, err := parent.Stat(".")
		if err != nil {
			return fail(err)
		}
		fileOwner, ok := info.Sys().(*syscall.Stat_t)
		dirOwner, dirOK := dir.Sys().(*syscall.Stat_t)
		if !ok || !dirOK || fileOwner.Uid != dirOwner.Uid {
			return fail(fmt.Errorf("certificate lease owner differs from directory"))
		}
		detached := false
		for {
			err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
			if err == nil {
				current, statErr := parent.Lstat(lockName)
				if statErr == nil && os.SameFile(info, current) {
					return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, nil
				}
				_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
				f.Close()
				if statErr != nil && !os.IsNotExist(statErr) {
					return nil, statErr
				}
				detached = true
				break
			}
			if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
				return fail(err)
			}
			select {
			case <-ctx.Done():
				return fail(ctx.Err())
			case <-time.After(10 * time.Millisecond):
			}
		}
		if !detached {
			return nil, errors.New("certificate lease acquisition failed")
		}
	}
}
func openLocalLease(parent *os.Root, name string) (*os.File, error) {
	for {
		f, err := parent.OpenFile(name, os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if err == nil {
			return f, nil
		}
		if !os.IsNotExist(err) {
			return nil, err
		}
		temp := localPrivatePrefix + "temp-" + uuid.NewString()
		f, err = parent.OpenFile(temp, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return nil, err
		}
		err = f.Chmod(0600)
		if err == nil {
			err = giveLocalFile(parent, f)
		}
		if err == nil {
			err = parent.Link(temp, name)
		}
		_ = parent.Remove(temp)
		if err == nil {
			return f, nil
		}
		f.Close()
		if !os.IsExist(err) {
			return nil, err
		}
	}
}
func giveLocalFile(parent *os.Root, f *os.File) error {
	if os.Geteuid() != 0 {
		return nil
	}
	info, err := parent.Stat(".")
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine certificate directory owner")
	}
	return f.Chown(int(st.Uid), int(st.Gid))
}
func readLocalRegular(parent *os.Root, name string) ([]byte, error) {
	f, err := parent.OpenFile(name, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("certificate cache entry %q is not regular", name)
	}
	return ioReadAllLocal(f)
}
