package helpers

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// FileErrorCause displays a filesystem error's underlying cause without its file names.
// Filesystem and ordinary wrappers beneath it are stripped from the displayed text.
// Known errno/filesystem causes are shown; an opaque filesystem cause gets a generic
// message, since its text can also contain paths. The original error chain remains
// available through errors.Is/As for classification.
// If no filesystem error is present, err is returned unchanged. Log the original error
// to retain the spool path, account ID and content hash for diagnosis.
func FileErrorCause(err error) error {
	var pathErr *fs.PathError
	var linkErr *os.LinkError
	var cause error
	switch {
	case errors.As(err, &pathErr):
		cause = pathErr.Err
	case errors.As(err, &linkErr):
		cause = linkErr.Err
	default:
		return err
	}
	return fileErrorCause{display: fileErrorDisplayLeaf(cause), original: err}
}

func fileErrorDisplayLeaf(err error) error {
unwrap:
	for err != nil {
		switch wrapped := err.(type) {
		case interface{ Unwrap() []error }:
			for _, child := range wrapped.Unwrap() {
				if child != nil {
					err = child
					continue unwrap
				}
			}
		case interface{ Unwrap() error }:
			if child := wrapped.Unwrap(); child != nil {
				err = child
				continue unwrap
			}
		}
		break
	}
	if errno, ok := err.(syscall.Errno); ok {
		return errno
	}
	for _, known := range []error{fs.ErrInvalid, fs.ErrPermission, fs.ErrExist, fs.ErrNotExist, fs.ErrClosed, io.EOF, io.ErrUnexpectedEOF, io.ErrShortWrite} {
		if errors.Is(err, known) {
			return known
		}
	}
	return errors.New("filesystem operation failed")
}

type fileErrorCause struct{ display, original error }

func (e fileErrorCause) Error() string { return e.display.Error() }
func (e fileErrorCause) Unwrap() error { return e.original }

// LinkOrCopyFile attempts to hardlink a file from src to dst. If linking fails
// (e.g., cross-device link), it falls back to copying the file.
func LinkOrCopyFile(src, dst string) error {
	// Ensure the destination directory exists
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for destination: %w", err)
	}

	// Try to hardlink first
	err := os.Link(src, dst)
	if err == nil {
		return nil
	}
	if os.IsExist(err) {
		return nil // Already exists
	}

	// Fallback to copying
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file for copy: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create destination file for copy: %w", err)
	}

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		dstFile.Close()
		os.Remove(dst)
		return fmt.Errorf("failed to copy file contents: %w", err)
	}

	if err := dstFile.Sync(); err != nil {
		dstFile.Close()
		return fmt.Errorf("failed to sync destination file: %w", err)
	}

	if err := dstFile.Close(); err != nil {
		return fmt.Errorf("failed to close destination file: %w", err)
	}

	return nil
}
