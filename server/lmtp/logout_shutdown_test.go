package lmtp

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/migadu/sora/logger"
)

// Server.Close cancels every session context before it logs the sessions out. A session
// idle between commands is the normal case at shutdown: nothing holds its lock, so Logout
// takes it and logs the session in full, without a lock warning (#1977).
func TestLogoutAtShutdownTakesAFreeLock(t *testing.T) {
	logs := &proxySessionLogs{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { logger.Swap(prev) })

	const sessions = 10
	for range sessions {
		s := newLogoutTestSession(t)
		s.User = testUser(t)
		s.cancel() // Server.Close
		if err := s.Logout(); err == nil {
			t.Fatal("Logout returned nil, want the 221 reply")
		}
	}

	logs.mu.Lock()
	out := logs.buf.String()
	logs.mu.Unlock()
	if n := strings.Count(out, "failed to acquire write lock"); n > 0 {
		t.Errorf("%d of %d idle sessions logged a lock warning at shutdown", n, sessions)
	}
	if n := strings.Count(out, "user=user@example.com"); n != sessions {
		t.Errorf("%d of %d logout lines name the user; the rest were logged without the lock:\n%s", n, sessions, out)
	}
}
