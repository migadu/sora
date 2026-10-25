//go:build unix

package logger

import (
	"os"

	"golang.org/x/sys/unix"
)

// redirect makes old's descriptor refer to the file f is open on, atomically.
func redirect(f, old *os.File) error {
	return unix.Dup2(int(f.Fd()), int(old.Fd()))
}
