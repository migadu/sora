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

// loginResultMessages are the messages a backend logs a login's result under.
// "authorization failed" is a login whose credentials checked out but that asked to act
// as another user.
var loginResultMessages = []string{
	`msg="authentication successful"`,
	`msg="authentication failed"`,
	`msg="authentication unavailable"`,
	`msg="authorization failed"`,
}

// RequireLoginResults checks the login-result lines captured for address. Each login's
// result is logged once, by its session, so the line carries the session's remote and
// session fields; want lists, in order, the parts each one must contain besides. The
// lines are written before the client gets the reply, so they are all there once the
// logins returned; the short wait only covers a slow writer.
func RequireLoginResults(t *testing.T, logs *LogBuffer, address string, want ...[]string) {
	t.Helper()
	var lines []string
	for deadline := time.Now().Add(2 * time.Second); ; {
		lines = lines[:0]
		logs.mu.Lock()
		captured := logs.buf.String()
		logs.mu.Unlock()
		for _, line := range strings.Split(captured, "\n") {
			if !strings.Contains(line, address) {
				continue
			}
			for _, msg := range loginResultMessages {
				if strings.Contains(line, msg) {
					lines = append(lines, line)
					break
				}
			}
		}
		if len(lines) >= len(want) || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(lines) != len(want) {
		t.Fatalf("%d login-result lines for %s, want %d (one per login):\n%s", len(lines), address, len(want), strings.Join(lines, "\n"))
	}
	for i, line := range lines {
		var missing []string
		for _, part := range append([]string{"remote=", "session="}, want[i]...) {
			if !strings.Contains(line, part) {
				missing = append(missing, part)
			}
		}
		if len(missing) > 0 {
			t.Errorf("login-result line %d lacks %q:\n%s", i+1, missing, line)
		}
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
