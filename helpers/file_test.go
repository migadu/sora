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
}
