//go:build integration

package lmtp

import (
	"context"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
)

// SetDefaultSieveScriptForTest replaces the embedded script before New compiles it.
// Tests using it must not run in parallel with other LMTP constructors.
func SetDefaultSieveScriptForTest(t *testing.T, script string) {
	t.Helper()
	original := defaultSieveScript
	defaultSieveScript = script
	t.Cleanup(func() { defaultSieveScript = original })
}

// RcptForTest answers RCPT TO:<to> on a session without a connection, against rdb, with
// the given RCPT timeout. ctx is the command's context, as go-smtp passes it.
func RcptForTest(ctx context.Context, rdb *resilient.ResilientDatabase, rcptTimeout time.Duration, to string) error {
	sessionCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &LMTPSession{
		backend: &LMTPServerBackend{
			name:            "test",
			hostname:        "test",
			rdb:             rdb,
			commandTimeouts: &CommandTimeouts{Rcpt: rcptTimeout},
		},
		ctx:       sessionCtx,
		cancel:    cancel,
		startTime: time.Now(),
	}
	s.Id = "rcpt-test"
	s.Protocol = "LMTP"
	s.ServerName = "test"
	s.RemoteIP = "127.0.0.1"
	s.mutexHelper = server.NewMutexTimeoutHelper(&s.mutex, sessionCtx, "LMTP", nil)
	return s.Rcpt(ctx, to, nil)
}
