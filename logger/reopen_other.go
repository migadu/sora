//go:build !unix

package logger

import (
	"errors"
	"os"
	"runtime"
)

func redirect(f, old *os.File) error {
	return errors.New("reopening the log file is not supported on " + runtime.GOOS)
}
