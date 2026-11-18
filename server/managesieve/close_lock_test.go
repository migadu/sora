package managesieve

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
	"github.com/migadu/sora/server"
)

// newCloseTestSession returns a logged-in session built as the accept path builds it
// (session context derived from the server's), and the cancel of the context it
// derives from, which Server.Close calls at shutdown.
func newCloseTestSession(t *testing.T) (*ManageSieveSession, context.CancelFunc) {
	t.Helper()
	appCtx, appCancel := context.WithCancel(context.Background())
	t.Cleanup(appCancel)
	srv := &ManageSieveServer{name: "close", hostname: "localhost", activeSessions: make(map[*ManageSieveSession]struct{})}
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	ctx, cancel := context.WithCancel(appCtx)
	s := &ManageSieveSession{server: srv, conn: c1, ctx: ctx, cancel: cancel, startTime: time.Now()}
	s.Protocol = "ManageSieve"
	s.ServerName = srv.name
	s.HostName = srv.hostname
	s.Id = "close-session"
	s.Stats = srv
	addr, err := server.NewAddress("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	s.User = server.NewUser(addr, 1)
	s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, ctx, "managesieve", s.InfoLog)
	srv.addSession(s)
	return s, appCancel
}

// Server.Close cancels every session context before the library tears the sessions
// down. A session closed then must still wait for the session lock held by a command,
// not tear down the state that command is working on (#1976).
func TestCloseAfterShutdownWaitsForSessionLock(t *testing.T) {
	s, shutdown := newCloseTestSession(t)

	s.mutex.Lock() // a command in flight holds the session lock
	shutdown()

	closed := make(chan struct{})
	go func() {
		s.Close()
		close(closed)
	}()

	select {
	case <-closed:
		cleared := s.User == nil
		s.mutex.Unlock()
		t.Fatalf("Close returned while a command held the session lock (session state cleared under the command: %v)", cleared)
	case <-time.After(300 * time.Millisecond):
	}

	s.mutex.Unlock() // the command finishes
	select {
	case <-closed:
	case <-time.After(server.MutexTimeout + time.Second):
		t.Fatal("Close did not finish once the command released the session lock")
	}
	if s.User != nil {
		t.Error("Close did not clear the session state")
	}
}

// A shutdown close with nothing holding the lock is the normal case and takes the
// lock without a lock message, although the session context is already cancelled.
func TestCloseAfterShutdownDoesNotWarn(t *testing.T) {
	logs := &authLockLogBuffer{}
	prev := logger.Swap(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { logger.Swap(prev) })

	for i := 0; i < 10; i++ {
		s, shutdown := newCloseTestSession(t)
		shutdown()
		s.Close()
	}
	if out := logs.String(); strings.Contains(out, "failed to acquire") {
		t.Errorf("shutdown close logged a lock message:\n%s", out)
	}
}
