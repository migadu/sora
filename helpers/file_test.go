package helpers

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestFileErrorCause(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "body")

	_, statErr := os.Stat(path)
	renameErr := os.Rename(path, filepath.Join(dir, "elsewhere"))
	plain := errors.New("plain failure")

	cases := []struct {
		name string
		err  error
		want error
	}{
		{"path error", statErr, fs.ErrNotExist},
		{"wrapped path error", fmt.Errorf("failed to create file %s: %w", path, statErr), fs.ErrNotExist},
		{"link error", fmt.Errorf("failed to move %s into place: %w", path, renameErr), fs.ErrNotExist},
		{"no file error", plain, plain},
		{"nested path and link errors", &fs.PathError{Op: "write", Path: path,
			Err: &os.LinkError{Op: "rename", Old: path, New: path + ".tmp", Err: syscall.EACCES}}, syscall.EACCES},
		{"nested link and path errors", &os.LinkError{Op: "rename", Old: path, New: path + ".tmp",
			Err: &fs.PathError{Op: "write", Path: path, Err: syscall.EROFS}}, syscall.EROFS},
		{"ordinary wrapper inside path error", &fs.PathError{Op: "write", Path: path,
			Err: fmt.Errorf("bad spool path %s: %w", path, syscall.EACCES)}, syscall.EACCES},
		{"multiple wrapped causes inside path error", &fs.PathError{Op: "write", Path: path,
			Err: fmt.Errorf("flush %s: %w; close %s.tmp: %w", path, syscall.EIO, path, syscall.EBADF)}, syscall.EIO},
		{"joined causes inside path error", &fs.PathError{Op: "write", Path: path,
			Err: errors.Join(fmt.Errorf("flush %s: %w", path, syscall.EIO), syscall.EBADF)}, syscall.EIO},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FileErrorCause(tc.err)
			if !errors.Is(got, tc.want) {
				t.Fatalf("FileErrorCause(%v) = %v, want %v", tc.err, got, tc.want)
			}
			if strings.Contains(got.Error(), dir) {
				t.Fatalf("FileErrorCause(%v) = %q still names the file", tc.err, got)
			}
		})
	}

	if got := FileErrorCause(nil); got != nil {
		t.Fatalf("FileErrorCause(nil) = %v, want nil", got)
	}

	// The cause is what a caller classifies: a full spool must stay recognisable.
	full := fmt.Errorf("failed to write file %s: %w", path, &fs.PathError{Op: "write", Path: path, Err: syscall.ENOSPC})
	if got := FileErrorCause(full); !errors.Is(got, syscall.ENOSPC) {
		t.Fatalf("FileErrorCause(%v) = %v, want ENOSPC", full, got)
	}
	// Sanitizing the displayed text must retain every wrapped cause for classifiers.
	joined := errors.Join(&fs.PathError{Op: "write", Path: path, Err: syscall.EACCES}, syscall.ENOSPC)
	got := FileErrorCause(joined)
	if !errors.Is(got, syscall.EACCES) || !errors.Is(got, syscall.ENOSPC) {
		t.Errorf("sanitized error lost a joined cause: %v", got)
	}
	var pathErr *fs.PathError
	if !errors.As(got, &pathErr) {
		t.Error("sanitized error lost structured filesystem cause")
	}
	opaque := &fs.PathError{Op: "write", Path: path, Err: errors.New("opaque fault at " + path)}
	if got := FileErrorCause(opaque); strings.Contains(got.Error(), path) {
		t.Errorf("opaque filesystem leaf exposed the path: %v", got)
	}
}

func TestIsInsufficientStorage(t *testing.T) {
	path := "/var/spool/sora/42/0123abcd"
	for _, tc := range []struct {
		errno syscall.Errno
		want  bool
	}{
		{syscall.ENOSPC, true},
		{syscall.EROFS, true},
		{syscall.EACCES, false},
		{syscall.EIO, false},
		{syscall.ENOENT, false},
	} {
		t.Run(tc.errno.Error(), func(t *testing.T) {
			staged := fmt.Errorf("failed to create file %s: %w", path, &fs.PathError{Op: "open", Path: path, Err: tc.errno})
			moved := fmt.Errorf("failed to move %s into place: %w", path, &os.LinkError{Op: "rename", Old: path + ".tmp", New: path, Err: tc.errno})
			for name, err := range map[string]error{
				"errno":        tc.errno,
				"path error":   staged,
				"link error":   moved,
				"display only": FileErrorCause(staged),
				"joined":       errors.Join(errors.New("cleanup failed"), staged),
			} {
				if got := IsInsufficientStorage(err); got != tc.want {
					t.Errorf("%s: IsInsufficientStorage(%v) = %v, want %v", name, err, got, tc.want)
				}
			}
		})
	}
	if IsInsufficientStorage(nil) {
		t.Error("IsInsufficientStorage(nil) = true")
	}
	if IsInsufficientStorage(errors.New("no space left on device")) {
		t.Error("IsInsufficientStorage matched an error by its text")
	}
}
