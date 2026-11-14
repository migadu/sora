//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

type defaultVacationQueue struct {
	mu    sync.Mutex
	items []defaultVacationItem
}

type defaultVacationItem struct {
	from, to, kind string
}

func (q *defaultVacationQueue) Enqueue(from, to, kind string, _ []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, defaultVacationItem{from: from, to: to, kind: kind})
	return nil
}

func (q *defaultVacationQueue) snapshot() []defaultVacationItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]defaultVacationItem(nil), q.items...)
}

// The embedded default currently has no vacation action. Substitute one before
// constructing the server to cover the default's real compile, delivery, and relay
// path, including persistent :days suppression and per-account isolation (#165).
func TestDefaultSieveVacationUsesRecipientOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	// No t.Parallel: the override is shared with other constructors in this package.
	lmtpserver.SetDefaultSieveScriptForTest(t, `require "vacation";
vacation :days 7 :subject "Away" "I am away.";
`)

	queue := &defaultVacationQueue{}
	srv, accountA := common.SetupLMTPServerWithOptions(t, lmtpserver.LMTPServerOptions{RelayQueue: queue})
	t.Cleanup(srv.Close)
	rdb := srv.ResilientDB
	accountB := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountAID, err := rdb.GetAccountIDByAddressWithRetry(ctx, accountA.Email)
	if err != nil {
		t.Fatalf("account A id: %v", err)
	}
	accountBID, err := rdb.GetAccountIDByAddressWithRetry(ctx, accountB.Email)
	if err != nil {
		t.Fatalf("account B id: %v", err)
	}
	const sender = "sender@example.net"

	deliver := func(recipient string, attempt int) {
		t.Helper()
		conn, err := net.DialTimeout("tcp", srv.Address, 5*time.Second)
		if err != nil {
			t.Fatalf("dial LMTP: %v", err)
		}
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			conn.Close()
			t.Fatalf("set LMTP deadline: %v", err)
		}
		client := smtp.NewClientLMTP(conn)
		defer client.Close()
		msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: default vacation %d\r\nMessage-ID: <default-vacation-%d-%d@example.net>\r\n\r\nhello\r\n",
			sender, recipient, attempt, time.Now().UnixNano(), attempt)
		if err := client.SendMail(sender, []string{recipient}, strings.NewReader(msg)); err != nil {
			t.Fatalf("deliver message %d: %v", attempt, err)
		}
	}
	assertReplies := func(wantFrom ...string) {
		t.Helper()
		items := queue.snapshot()
		if len(items) != len(wantFrom) {
			t.Fatalf("vacation handoffs = %d, want %d: %+v", len(items), len(wantFrom), items)
		}
		for i, from := range wantFrom {
			if item := items[i]; item.kind != "vacation" || item.from != from || item.to != sender {
				t.Errorf("handoff %d = %+v, want vacation from %s to %s", i, item, from, sender)
			}
		}
	}
	assertRecords := func(accountID int64, want int) {
		t.Helper()
		var count int
		if err := rdb.QueryRowWithRetry(ctx, `SELECT count(*) FROM vacation_responses WHERE account_id = $1 AND sender_address = $2`, accountID, sender).Scan(&count); err != nil {
			t.Fatalf("count vacation records: %v", err)
		}
		if count != want {
			t.Fatalf("vacation records for account %d = %d, want %d", accountID, count, want)
		}
	}

	deliver(accountA.Email, 1)
	assertReplies(accountA.Email)

	deliver(accountA.Email, 2)
	assertReplies(accountA.Email)
	assertRecords(accountAID, 1)

	// The shared compiled script must bind each delivery to its own account.
	deliver(accountB.Email, 3)
	assertReplies(accountA.Email, accountB.Email)
	assertRecords(accountBID, 1)

	// Expire A's seven-day window without sleeping; B's record stays current.
	if _, err := rdb.ExecWithRetry(ctx, `UPDATE vacation_responses SET response_date = clock_timestamp() - interval '8 days' WHERE account_id = $1 AND sender_address = $2`, accountAID, sender); err != nil {
		t.Fatalf("expire vacation period: %v", err)
	}
	deliver(accountA.Email, 4)
	assertReplies(accountA.Email, accountB.Email, accountA.Email)
	assertRecords(accountAID, 1) // the new period supersedes the expired one
	deliver(accountB.Email, 5)
	assertReplies(accountA.Email, accountB.Email, accountA.Email)
	assertRecords(accountBID, 1)
}
