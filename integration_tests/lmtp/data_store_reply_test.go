//go:build integration

package lmtp_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server/lmtp"
)

// lockMailboxes stalls the INBOX lookup that stores a kept message: it reads
// mailboxes, which the returned transaction holds locked until the test ends. It
// returns the backend pid of the lock holder.
func lockMailboxes(t *testing.T, rdb *resilient.ResilientDatabase) int {
	t.Helper()
	ctx := context.Background()
	tx, err := rdb.GetDatabase().GetWritePool().Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err := tx.Exec(ctx, "LOCK TABLE mailboxes IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatalf("lock mailboxes: %v", err)
	}
	var pid int
	if err := tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&pid); err != nil {
		t.Fatalf("backend pid: %v", err)
	}
	return pid
}

// waitBlockedBy waits until some session waits on a lock the backend holder holds.
func waitBlockedBy(t *testing.T, rdb *resilient.ResilientDatabase, holder int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var blocked bool
		err := rdb.GetDatabase().GetWritePool().QueryRow(context.Background(),
			"SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))",
			holder).Scan(&blocked)
		if err != nil {
			t.Fatalf("pg_stat_activity: %v", err)
		}
		if blocked {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the store never waited on the mailboxes lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func storeReplyMessage(account common.TestAccount, kind string) string {
	marker := fmt.Sprintf("%s-%d", kind, time.Now().UnixNano())
	return "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: " + marker +
		"\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nbody\r\n"
}

// The DATA command's own cap firing while the store waits on the database is a slow
// server, not a shutdown: the message is deferred with 451 4.3.0 "Message processing
// timed out", never 421 4.2.1 "service shutting down" (#1962).
func TestLMTP_DataCapTimeoutReply(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// The query_timeout (30s by default) stays far above the cap: only the cap fires.
	rdb := common.SetupTestDatabase(t)
	srv, account := common.SetupLMTPServerWithDatabase(t, rdb, lmtp.LMTPServerOptions{
		CommandTimeoutOverrides: map[string]time.Duration{"data": 500 * time.Millisecond},
	})
	defer srv.Close()

	stall := func() { lockMailboxes(t, rdb) }
	response := deliverLMTPRawBeforeData(t, srv.Address, "sender@example.com", account.Email,
		storeReplyMessage(account, "data-cap"), stall)
	if !strings.HasPrefix(response, "451 4.3.0") || !strings.Contains(response, "Message processing timed out") {
		t.Fatalf("DATA = %q, want 451 4.3.0 Message processing timed out", response)
	}
}

// A shutdown while the store waits on the database answers the message 421 4.2.1
// "service shutting down", not the 451 of a DATA cap that fired (#1962), and then
// closes the connection, as a 421 says it does (RFC 5321 section 3.8, #1990).
// Cancelling the application context is the server's shutdown signal.
func TestLMTP_DataShutdownReply(t *testing.T) {
	testDataShutdownReply(t, func(shutdown context.CancelFunc, _ *lmtp.LMTPServerBackend) {
		shutdown()
	})
}

// cmd/sora shuts the server down by cancelling the application context and, from a
// watcher on it, calling Close straight after. Close must let the session answer the
// message it is storing before it closes the connection (#1990), which once closed it
// before the session had written the 421.
func TestLMTP_DataShutdownReplyBeforeClose(t *testing.T) {
	testDataShutdownReply(t, func(shutdown context.CancelFunc, backend *lmtp.LMTPServerBackend) {
		shutdown()
		backend.Close()
	})
}

// testDataShutdownReply stalls a message's store, runs stop, and wants the 421 4.2.1
// reply followed by the end of the connection.
func testDataShutdownReply(t *testing.T, stop func(shutdown context.CancelFunc, backend *lmtp.LMTPServerBackend)) {
	common.SkipIfDatabaseUnavailable(t)

	appCtx, shutdown := context.WithCancel(context.Background())
	defer shutdown()
	rdb := common.SetupTestDatabase(t)
	srv, account := common.SetupLMTPServerWithContext(t, appCtx, rdb, lmtp.LMTPServerOptions{
		CommandTimeoutOverrides: map[string]time.Duration{"data": time.Minute},
	})
	defer srv.Close()

	c, err := NewLMTPClient(srv.Address)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.conn.Close()
	for _, step := range []struct{ cmd, want string }{
		{"LHLO test.example.com", "250"},
		{"MAIL FROM:<sender@example.com>", "250"},
		{fmt.Sprintf("RCPT TO:<%s>", account.Email), "250"},
		{"DATA", "354"},
	} {
		if err := c.SendCommand(step.cmd); err != nil {
			t.Fatalf("%s: %v", step.cmd, err)
		}
		lines, err := c.ReadMultilineResponse()
		if err != nil {
			t.Fatalf("%s response: %v", step.cmd, err)
		}
		if last := lines[len(lines)-1]; !strings.HasPrefix(last, step.want) {
			t.Fatalf("%s: got %s", step.cmd, last)
		}
	}

	holder := lockMailboxes(t, rdb)
	if err := c.SendCommand(storeReplyMessage(account, "data-shutdown") + "\r\n."); err != nil {
		t.Fatalf("send message: %v", err)
	}
	waitBlockedBy(t, rdb, holder)
	stop(shutdown, srv.Server.(*lmtp.LMTPServerBackend))

	if err := c.conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("read deadline: %v", err)
	}
	response, err := c.ReadResponse()
	if err != nil {
		t.Fatalf("DATA per-recipient response: %v", err)
	}
	if !strings.HasPrefix(response, "421 4.2.1") || !strings.Contains(response, "service shutting down") {
		t.Fatalf("DATA = %q, want 421 4.2.1 service shutting down", response)
	}
	if line, err := c.ReadResponse(); !errors.Is(err, io.EOF) {
		t.Fatalf("after the 421: read %q, %v; want the connection closed (EOF)", line, err)
	}
}
