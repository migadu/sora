package helpers

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// FileErrorCause returns the cause of a filesystem error without the file names it
// carries: the Err of the *fs.PathError or *os.LinkError in err's chain, or err itself
// when there is none. A reply to a client is built from the cause, since server paths
// mean nothing to the client and name local details (spool layout, account ids, content
// hashes); the full error belongs in the log. errors.Is still matches the cause, so
// syscall.ENOSPC or syscall.EROFS is recognised in the result.
func FileErrorCause(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return linkErr.Err
	}
	return err
}

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
