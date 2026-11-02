//go:build integration

package pop3_test

import (
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/pop3"
)

// A POP3 session's deletions are applied at QUIT: stopping the node under a logged-in
// session loses them, and the client downloads those messages again. So the node reports
// logged-in POP3 sessions among those it must let finish (backend maintenance waits on
// them): from login until the session ends. Started never goes back.
func TestPOP3_DrainSessionsCountLoggedInSessions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()
	s, ok := server.Server.(*pop3.POP3Server)
	if !ok {
		t.Fatalf("server is %T, want *pop3.POP3Server", server.Server)
	}

	expect := func(wantOpen, wantStarted int64, when string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			open, started := s.DrainSessions()
			if open == wantOpen && started == wantStarted {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: drain sessions = %d open, %d started; want %d open, %d started", when, open, started, wantOpen, wantStarted)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	command := func(c *POP3Client, cmd string) {
		t.Helper()
		if err := c.SendCommand(cmd); err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		resp, err := c.ReadResponse()
		if err != nil || !strings.HasPrefix(resp, "+OK") {
			t.Fatalf("%s: %q, %v", cmd, resp, err)
		}
	}

	c, err := NewPOP3Client(server.Address)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	expect(0, 0, "connected, not logged in")

	command(c, "USER "+account.Email)
	command(c, "PASS "+account.Password)
	expect(1, 1, "logged in")

	command(c, "QUIT")
	expect(0, 1, "after QUIT")
}
