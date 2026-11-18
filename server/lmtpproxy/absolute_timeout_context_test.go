package lmtpproxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// startIdleTestSession starts a real proxy session on an in-memory connection, reads
// its greeting and leaves the client idle. It returns the session, the client end and
// a channel closed when handleConnection returns.
func startIdleTestSession(t *testing.T, absoluteTimeout time.Duration) (*Session, net.Conn, <-chan struct{}) {
	t.Helper()
	srv, err := New(context.Background(), nil, "test-host", ServerOptions{
		Name: "idle", RemoteAddrs: []string{"127.0.0.1:1"}, RemotePort: 24, ConnectTimeout: time.Second,
		AbsoluteSessionTimeout: absoluteTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Stop() })

	front, serverEnd := net.Pipe()
	sess := newSession(srv, serverEnd, nil)
	done := make(chan struct{})
	go func() { defer close(done); sess.handleConnection() }()
	t.Cleanup(func() {
		front.Close()
		<-done
	})
	front.SetDeadline(time.Now().Add(10 * time.Second))
	if greeting := readReply(t, bufio.NewReader(front)); !strings.HasPrefix(greeting, "220 ") {
		t.Fatalf("greeting = %q", greeting)
	}
	return sess, front, done
}

// waitSessionEnd fails the test unless the session ends, and the client sees its
// connection closed, within bound.
func waitSessionEnd(t *testing.T, front net.Conn, done <-chan struct{}, bound time.Duration, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(bound):
		t.Fatalf("session still running %v after %s", bound, what)
	}
	front.SetReadDeadline(time.Now().Add(bound))
	if _, err := io.Copy(io.Discard, front); err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("client connection still open %v after %s", bound, what)
		}
	}
}

// TestContextCancellationDetectedInCommandLoop: cancelling the session context (what
// server shutdown and the absolute timeout do) ends a session that is waiting in the
// command loop for the client's next command. The command read has no deadline here
// (no auth idle timeout), so only the session's context watchdog, which closes the
// connections, can unblock it.
func TestContextCancellationDetectedInCommandLoop(t *testing.T) {
	sess, front, done := startIdleTestSession(t, 0)
	sess.cancel()
	waitSessionEnd(t, front, done, 2*time.Second, "the session context was cancelled")
}

// TestAbsoluteTimeoutCallsCancel: the absolute session timeout ends a session whose
// client sends nothing after the greeting, by cancelling the session context.
func TestAbsoluteTimeoutCallsCancel(t *testing.T) {
	const absoluteTimeout = 300 * time.Millisecond
	sess, front, done := startIdleTestSession(t, absoluteTimeout)
	start := time.Now()
	select {
	case <-sess.ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatalf("session context not cancelled 5s into a %v absolute timeout", absoluteTimeout)
	}
	waitSessionEnd(t, front, done, 2*time.Second, "the absolute timeout")
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("session ended %v after the greeting; the absolute timeout is %v", elapsed, absoluteTimeout)
	}
}
