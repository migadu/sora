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
}
