package server

import (
	"context"
	"net"
	"sync"
	"time"
)

// SessionGroup counts a server's sessions so that shutdown can wait for them.
//
// A bare sync.WaitGroup cannot do this: the accept loop registers each new
// session while shutdown may already be waiting, and sync.WaitGroup requires
// that "calls with a positive delta that occur when the counter is zero must
// happen before a Wait". SessionGroup registers under a mutex that Drain also
// takes, and refuses to register once Drain has begun, so every registration
// happens before the Wait and no session starts after shutdown stopped waiting.
type SessionGroup struct {
	mu       sync.Mutex
	draining bool
	wg       sync.WaitGroup
}

// Add registers one session and reports true, or reports false once Drain has
// begun, in which case the caller must not start the session. Each true is
// matched by one Done.
func (g *SessionGroup) Add() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.draining {
		return false
	}
	g.wg.Add(1)
	return true
}

// Done marks a session registered by Add as ended.
func (g *SessionGroup) Done() {
	g.wg.Done()
}

// Go runs session in a new goroutine registered in the group and reports true,
// or reports false without running it once Drain has begun.
func (g *SessionGroup) Go(session func()) bool {
	if !g.Add() {
		return false
	}
	go func() {
		defer g.Done()
		session()
	}()
	return true
}

// Drain refuses further sessions and waits up to timeout for the registered
// ones to end. It reports whether they all did.
func (g *SessionGroup) Drain(timeout time.Duration) bool {
	g.BeginDrain()

	done := make(chan struct{})
	go func() {
		g.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// BeginDrain stops admission before shutdown notifies existing sessions. It
// uses Add's mutex, so every accepted registration precedes the later Wait.
func (g *SessionGroup) BeginDrain() {
	g.mu.Lock()
	g.draining = true
	g.mu.Unlock()
}

// IsDraining reports whether shutdown has closed session admission.
func (g *SessionGroup) IsDraining() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.draining
}

// GuardInitialization interrupts an accepted connection's handshake on shutdown.
// Call the returned function after publishing the initialized session, or when
// initialization fails. A session published after shutdown's notification
// snapshot must close itself; one published earlier is covered by that snapshot.
// Once initialization ends, normal protocol shutdown replies own the connection.
func (g *SessionGroup) GuardInitialization(ctx context.Context, conn net.Conn) func() {
	closeRaw := func() {
		if raw := RawConn(conn); raw != nil {
			raw.Close()
		}
	}
	stopClose := context.AfterFunc(ctx, closeRaw)
	return func() {
		stopClose()
		if g.IsDraining() || ctx.Err() != nil {
			closeRaw()
		}
	}
}
