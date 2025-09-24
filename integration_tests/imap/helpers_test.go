//go:build integration

package imap_test

import (
	"bytes"
	"log"
	"os"
	"strings"

	imap "github.com/emersion/go-imap/v2"
)

// LogCapture helps capture log output for verification
type LogCapture struct {
	original *os.File
	buffer   *bytes.Buffer
}

// NewLogCapture creates a new log capture that redirects standard log output to a buffer
func NewLogCapture() *LogCapture {
	lc := &LogCapture{
		original: os.Stderr,
		buffer:   &bytes.Buffer{},
	}

	// Redirect log output to our buffer
	log.SetOutput(lc.buffer)
	return lc
}

// Stop restores the original log output and returns captured logs
func (lc *LogCapture) Stop() string {
	log.SetOutput(lc.original)
	return lc.buffer.String()
}

// ContainsProxyLog checks if the captured logs contain proxy= entries
func (lc *LogCapture) ContainsProxyLog() bool {
	logs := lc.buffer.String()
	return strings.Contains(logs, "proxy=")
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
