//go:build integration

package imap_test

import (
	"bytes"
	"log"
	"os"
	"strings"
	"sync"

	imap "github.com/emersion/go-imap/v2"
)

// LogCapture helps capture log output for verification. It guards the buffer
// with a mutex: background server goroutines keep logging while the test
// reads the captured output.
type LogCapture struct {
	original *os.File
	mu       sync.Mutex
	buffer   bytes.Buffer
}

// NewLogCapture creates a new log capture that redirects standard log output to a buffer
func NewLogCapture() *LogCapture {
	lc := &LogCapture{
		original: os.Stderr,
	}

	// Redirect log output to our buffer
	log.SetOutput(lc)
	return lc
}

func (lc *LogCapture) Write(p []byte) (int, error) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.buffer.Write(p)
}

// Stop restores the original log output and returns captured logs
func (lc *LogCapture) Stop() string {
	log.SetOutput(lc.original)
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.buffer.String()
}

// ContainsProxyLog checks if the captured logs contain proxy= entries
func (lc *LogCapture) ContainsProxyLog() bool {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return strings.Contains(lc.buffer.String(), "proxy=")
}

// Helper function to check if a flag is present in a slice of flags
func containsFlag(flags []imap.Flag, flag imap.Flag) bool {
	for _, f := range flags {
		if f == flag {
			return true
		}
	}
	return false
}
