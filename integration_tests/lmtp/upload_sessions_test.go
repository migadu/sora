//go:build integration

package lmtp_test

import (
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtp"
)

// Every LMTP session can deliver, so the node reports each as an upload session (backend
// maintenance waits on them), from LHLO (where go-smtp starts the session) to close.
// Started never goes back.
func TestLMTP_UploadSessionsCountConnections(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, _ := common.SetupLMTPServer(t)
	defer server.Close()
	backend, ok := server.Server.(*lmtp.LMTPServerBackend)
	if !ok {
		t.Fatalf("server is %T, want *lmtp.LMTPServerBackend", server.Server)
	}

	expect := func(wantOpen, wantStarted int64, when string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			open, started := backend.UploadSessions()
			if open == wantOpen && started == wantStarted {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: upload sessions = %d open, %d started; want %d open, %d started", when, open, started, wantOpen, wantStarted)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	expect(0, 0, "before any connection")
	c, _ := lhloSession(t, server.Address)
	expect(1, 1, "after LHLO")
	c.Close()
	expect(0, 1, "after close")
}
