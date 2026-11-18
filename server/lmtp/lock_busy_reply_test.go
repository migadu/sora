package lmtp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/server"
)

// wantBusyReply checks the reply to a command that could not take the session lock in time:
// 451 4.4.5, a temporary failure the session carries on after. A 421 would announce that
// the server closes the connection (RFC 5321 sections 3.8 and 4.2.2), which it does not
// do (#2047).
func wantBusyReply(t *testing.T, command string, err error) {
	t.Helper()
	var reply *smtp.SMTPError
	if !errors.As(err, &reply) {
		t.Fatalf("%s = %v, want an SMTP reply", command, err)
	}
	if reply.Code != 451 || reply.EnhancedCode != (smtp.EnhancedCode{4, 4, 5}) || reply.Message != "Server busy, try again later" {
		t.Fatalf("%s = %d %v %q, want 451 4.4.5 Server busy, try again later", command, reply.Code, reply.EnhancedCode, reply.Message)
	}
}

// busySession is a session whose lock another holder keeps past server.MutexTimeout.
// release lets the holder go.
func busySession(t *testing.T) (s *LMTPSession, release func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s = &LMTPSession{
		backend:   &LMTPServerBackend{name: "test", hostname: "test"},
		ctx:       ctx,
		cancel:    cancel,
		startTime: time.Now(),
	}
	s.Id = "lock-busy-test"
	s.Protocol = "LMTP"
	s.ServerName = "test"
	s.RemoteIP = "127.0.0.1"
	s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, ctx, "LMTP", nil)
	s.mutex.Lock()
	released := false
	release = func() {
		if !released {
			released = true
			s.mutex.Unlock()
		}
	}
	t.Cleanup(release)
	return s, release
}

func TestLockBusyReply(t *testing.T) {
	t.Run("MAIL", func(t *testing.T) {
		t.Parallel()
		s, release := busySession(t)
		wantBusyReply(t, "MAIL", s.Mail(context.Background(), "sender@example.com", nil))

		// The session goes on: the same MAIL is accepted once the lock is free.
		release()
		if err := s.Mail(context.Background(), "sender@example.com", nil); err != nil {
			t.Fatalf("MAIL after the lock was released = %v, want accepted", err)
		}
	})
	t.Run("DATA", func(t *testing.T) {
		t.Parallel()
		s, _ := busySession(t)
		wantBusyReply(t, "DATA", s.Data(context.Background(), strings.NewReader("Subject: x\r\n\r\nbody\r\n")))
	})
}
