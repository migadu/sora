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
// them): from login until the session ends.
func TestPOP3_DrainSessionsCountLoggedInSessions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()
	s := pop3Server(t, server)

	c, err := NewPOP3Client(server.Address)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()
	expectOpenDrainSessions(t, s, 0, "connected, not logged in")

	pop3Command(t, c, "USER "+account.Email, "+OK")
	pop3Command(t, c, "PASS "+account.Password, "+OK")
	expectOpenDrainSessions(t, s, 1, "logged in")

	pop3Command(t, c, "QUIT", "+OK")
	expectOpenDrainSessions(t, s, 0, "after QUIT")
}

// A backend refusing new sessions (in maintenance, past refuse_after) turns logins away
// with a temporary failure, -ERR [SYS/TEMP], and does not count them. A session logged in
// before carries on.
func TestPOP3_MaintenanceRefusesNewLogins(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupPOP3Server(t)
	defer server.Close()
	s := pop3Server(t, server)
	connect := func() *POP3Client {
		t.Helper()
		c, err := NewPOP3Client(server.Address)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}

	before := connect()
	pop3Command(t, before, "USER "+account.Email, "+OK")
	pop3Command(t, before, "PASS "+account.Password, "+OK")
	expectOpenDrainSessions(t, s, 1, "logged in before maintenance")

	server.MaintenanceGate.SetRefusing(true)
	refused := connect()
	pop3Command(t, refused, "USER "+account.Email, "+OK")
	pop3Command(t, refused, "PASS "+account.Password, "-ERR [SYS/TEMP]")
	expectOpenDrainSessions(t, s, 1, "after the refused login")
	pop3Command(t, before, "STAT", "+OK")

	server.MaintenanceGate.SetRefusing(false)
	after := connect()
	pop3Command(t, after, "USER "+account.Email, "+OK")
	pop3Command(t, after, "PASS "+account.Password, "+OK")
	expectOpenDrainSessions(t, s, 2, "after accepting again")
}

func pop3Server(t *testing.T, server *common.TestServer) *pop3.POP3Server {
	t.Helper()
	s, ok := server.Server.(*pop3.POP3Server)
	if !ok {
		t.Fatalf("server is %T, want *pop3.POP3Server", server.Server)
	}
	return s
}

func expectOpenDrainSessions(t *testing.T, s *pop3.POP3Server, want int64, when string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		open := s.DrainSessions()
		if open == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d drain sessions open, want %d", when, open, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func pop3Command(t *testing.T, c *POP3Client, cmd, wantPrefix string) {
	t.Helper()
	if err := c.SendCommand(cmd); err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	resp, err := c.ReadResponse()
	if err != nil || !strings.HasPrefix(resp, wantPrefix) {
		t.Fatalf("%s: %q, %v; want %q", cmd, resp, err, wantPrefix)
	}
}
