package pop3

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
	serverPkg "github.com/migadu/sora/server"
)

// newCloseTestSession returns a logged-in session holding a message listing, built
// as the accept path builds it (session context derived from the server's), and the
// cancel of the context it derives from, which Server.Close calls at shutdown.
func newCloseTestSession(t *testing.T) (*POP3Session, context.CancelFunc) {
	t.Helper()
	appCtx, appCancel := context.WithCancel(context.Background())
	t.Cleanup(appCancel)
	srv := &POP3Server{name: "close", hostname: "localhost", activeSessions: make(map[*POP3Session]struct{})}
	ctx, cancel := context.WithCancel(appCtx)
	s := &POP3Session{
		server:    srv,
		ctx:       ctx,
		cancel:    cancel,
		startTime: time.Now(),
		messages:  []db.POP3Message{{UID: 1, Size: 10}},
		deleted:   map[int]bool{0: true},
	}
	s.Protocol = "POP3"
	s.ServerName = srv.name
	s.HostName = srv.hostname
	addr, err := serverPkg.NewAddress("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	s.User = serverPkg.NewUser(addr, 1)
	s.mutexHelper = serverPkg.NewMutexTimeoutHelper(&s.mutex, ctx, "pop3", s.InfoLog)
	srv.addSession(s)
	return s, appCancel
}

// Server.Close cancels every session context before the library tears the sessions
// down. A session closed then must still wait for the session lock held by a command,
// not clear the state that command is working on (#1947).
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
		cleared := s.messages == nil && s.deleted == nil
		s.mutex.Unlock()
		t.Fatalf("Close returned while a command held the session lock (session state cleared under the command: %v)", cleared)
	case <-time.After(300 * time.Millisecond):
	}

	s.mutex.Unlock() // the command finishes
	select {
	case <-closed:
	case <-time.After(serverPkg.MutexTimeout + time.Second):
		t.Fatal("Close did not finish once the command released the session lock")
	}
	if s.messages != nil || s.deleted != nil || s.User != nil {
		t.Error("Close did not clear the session state")
	}
}

// syncBuffer is a bytes.Buffer safe to read while a logger may still write to it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A shutdown close with nothing holding the lock is the normal case and takes the
// lock without a warning, although the session context is already cancelled.
func TestCloseAfterShutdownDoesNotWarn(t *testing.T) {
	var logs syncBuffer
	prev := logger.Swap(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { logger.Swap(prev) })

	for i := 0; i < 10; i++ {
		s, shutdown := newCloseTestSession(t)
		shutdown()
		s.Close()
	}
	if out := logs.String(); strings.Contains(out, "failed to acquire") {
		t.Errorf("shutdown close logged a lock warning:\n%s", out)
	}
}
