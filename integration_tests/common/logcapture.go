package common

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
)

// LogBuffer holds what the logger package wrote while a test ran (see CaptureLogs).
// Servers keep logging from their own goroutines while the test reads it.
type LogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *LogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// WaitForLine returns the first captured line containing every one of parts, waiting
// up to ten seconds: a server often logs after it has replied to the client.
func (b *LogBuffer) WaitForLine(t *testing.T, parts ...string) string {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; {
		b.mu.Lock()
		logs := b.buf.String()
		b.mu.Unlock()
		for _, line := range strings.Split(logs, "\n") {
			found := true
			for _, p := range parts {
				found = found && strings.Contains(line, p)
			}
			if found {
				return line
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no log line contains %q", parts)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// CaptureLogs routes the logger package's INFO-and-above output into a buffer until the
// test ends. It swaps the logger itself, so it holds whatever an earlier test's
// logger.Initialize did with the output, which redirecting the log package does not.
func CaptureLogs(t *testing.T) *LogBuffer {
	b := &LogBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(b, nil)))
	t.Cleanup(func() { logger.Swap(prev) })
	return b
}
