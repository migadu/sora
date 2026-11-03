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
// cache) holds nothing up. Started never goes back.
func TestLMTP_DrainSessionsCountTransactions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	server, account := common.SetupLMTPServer(t)
	defer server.Close()
	backend, ok := server.Server.(*lmtp.LMTPServerBackend)
	if !ok {
		t.Fatalf("server is %T, want *lmtp.LMTPServerBackend", server.Server)
	}

	expect := func(wantOpen, wantStarted int64, when string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			open, started := backend.DrainSessions()
			if open == wantOpen && started == wantStarted {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: drain sessions = %d open, %d started; want %d open, %d started", when, open, started, wantOpen, wantStarted)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	command := func(c *LMTPClient, cmd, wantPrefix string) {
		t.Helper()
		if err := c.SendCommand(cmd); err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		resp, err := c.ReadResponse()
		if err != nil || !strings.HasPrefix(resp, wantPrefix) {
			t.Fatalf("%s: %q, %v", cmd, resp, err)
		}
	}

	expect(0, 0, "before any connection")
	probe, _ := lhloSession(t, server.Address)
	expect(0, 0, "a connection that only greeted")
	probe.Close()
	expect(0, 0, "after the probe left")

	c, _ := lhloSession(t, server.Address)
	command(c, "MAIL FROM:<sender@example.com>", "250")
	expect(1, 1, "in a transaction")
	command(c, "RCPT TO:<"+account.Email+">", "250")
	command(c, "RSET", "250")
	expect(0, 1, "idle between transactions")

	command(c, "MAIL FROM:<sender@example.com>", "250")
	expect(1, 2, "in the next transaction")
	c.Close()
	expect(0, 2, "after the connection closed mid-transaction")
}
