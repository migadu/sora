package helpers

import (
	"errors"
	"io"
	"io/fs"
	"os"
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
