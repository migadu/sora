//go:build integration

package lmtp_test

import (
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/lmtp"
)

// LMTP stages uploads only inside a transaction (MAIL to the end of DATA, or RSET), so the
// node reports transactions, not connections: a connection that only greeted (a
// monitoring probe sending LHLO) or sits idle between transactions (an MTA's connection
// cache) holds nothing up.
func TestLMTP_DrainSessionsCountTransactions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupLMTPServer(t)
	defer server.Close()
	backend := lmtpBackend(t, server)

	expectOpenTransactions(t, backend, 0, "before any connection")
	probe, _ := lhloSession(t, server.Address)
	expectOpenTransactions(t, backend, 0, "a connection that only greeted")
	probe.Close()
	expectOpenTransactions(t, backend, 0, "after the probe left")

	c, _ := lhloSession(t, server.Address)
	lmtpCommand(t, c, "MAIL FROM:<sender@example.com>", "250")
	expectOpenTransactions(t, backend, 1, "in a transaction")
	lmtpCommand(t, c, "RCPT TO:<"+account.Email+">", "250")
	lmtpCommand(t, c, "RSET", "250")
	expectOpenTransactions(t, backend, 0, "idle between transactions")

	lmtpCommand(t, c, "MAIL FROM:<sender@example.com>", "250")
	expectOpenTransactions(t, backend, 1, "in the next transaction")
	c.Close()
	expectOpenTransactions(t, backend, 0, "after the connection closed mid-transaction")
}

// A backend refusing new sessions (in maintenance, past refuse_after) refuses new
// transactions with 451 4.3.2 (RFC 3463: system not accepting network messages), on a new
// connection or an old one, and does not count them; the sender retries later. A
// transaction under way carries on.
func TestLMTP_MaintenanceRefusesNewTransactions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupLMTPServer(t)
	defer server.Close()
	backend := lmtpBackend(t, server)

	under, _ := lhloSession(t, server.Address)
	defer under.Close()
	lmtpCommand(t, under, "MAIL FROM:<sender@example.com>", "250")
	expectOpenTransactions(t, backend, 1, "a transaction under way")

	server.MaintenanceGate.SetRefusing(true)
	refused, _ := lhloSession(t, server.Address)
	defer refused.Close()
	lmtpCommand(t, refused, "MAIL FROM:<sender@example.com>", "451 4.3.2")
	lmtpCommand(t, under, "RCPT TO:<"+account.Email+">", "250")
	expectOpenTransactions(t, backend, 1, "after the refused transaction")
	lmtpCommand(t, under, "RSET", "250")
	lmtpCommand(t, under, "MAIL FROM:<sender@example.com>", "451 4.3.2")
	expectOpenTransactions(t, backend, 0, "a new transaction on the old connection")

	server.MaintenanceGate.SetRefusing(false)
	lmtpCommand(t, refused, "MAIL FROM:<sender@example.com>", "250")
	expectOpenTransactions(t, backend, 1, "after accepting again")
}

func lmtpBackend(t *testing.T, server *common.TestServer) *lmtp.LMTPServerBackend {
	t.Helper()
	backend, ok := server.Server.(*lmtp.LMTPServerBackend)
	if !ok {
		t.Fatalf("server is %T, want *lmtp.LMTPServerBackend", server.Server)
	}
	return backend
}

func expectOpenTransactions(t *testing.T, backend *lmtp.LMTPServerBackend, want int64, when string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		open := backend.DrainSessions()
		if open == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d transactions open, want %d", when, open, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func lmtpCommand(t *testing.T, c *LMTPClient, cmd, wantPrefix string) {
	t.Helper()
	if err := c.SendCommand(cmd); err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	resp, err := c.ReadResponse()
	if err != nil || !strings.HasPrefix(resp, wantPrefix) {
		t.Fatalf("%s: %q, %v; want %q", cmd, resp, err, wantPrefix)
	}
}
