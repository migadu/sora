package lmtp

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
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

// A command (a DATA reading the body) still holds the session lock when Server.Close
// cancels the session and logs it out. Logout must not wait for the lock, and the lock it
// could not take is one session lock timeout, like any other the helper gives up on (#2027).
func TestLogoutAtShutdownCountsAHeldLockAsATimeout(t *testing.T) {
	s := newLogoutTestSession(t)
	timeouts := metrics.SessionLockTimeouts.WithLabelValues("lmtp", "write")
	before := testutil.ToFloat64(timeouts)

	s.mutex.Lock() // the command
	s.cancel()     // Server.Close
	start := time.Now()
	err := s.Logout()
	waited := time.Since(start)
	s.mutex.Unlock()

	if err == nil {
		t.Error("Logout returned nil, want the 221 reply")
	}
	if waited > 500*time.Millisecond {
		t.Errorf("Logout waited %v for the lock of a cancelled session, want a prompt return", waited)
	}
	if got := testutil.ToFloat64(timeouts) - before; got != 1 {
		t.Errorf("sora_session_lock_timeouts_total{protocol=\"lmtp\",lock_type=\"write\"} rose by %v, want 1", got)
	}

	// The helper's abandoned attempt takes the lock once the command releases it, and
	// must drop it again.
	deadline := time.Now().Add(time.Second)
	for !s.mutex.TryLock() {
		if time.Now().After(deadline) {
			t.Fatal("the session lock is still held a second after the command released it")
		}
		time.Sleep(time.Millisecond)
	}
	s.mutex.Unlock()
}
