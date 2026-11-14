//go:build integration

package httpapi

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/adminapi"
)

// captureRelayQueue records the message types enqueued for relay.
type captureRelayQueue struct {
	mu    sync.Mutex
	types []string
}

func (q *captureRelayQueue) Enqueue(from, to, messageType string, messageBytes []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.types = append(q.types, messageType)
	return nil
}

func (q *captureRelayQueue) enqueued() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]string(nil), q.types...)
}

// countingRelayWorker counts the wake-ups the relay worker is sent.
type countingRelayWorker struct{ notified atomic.Int32 }

func (w *countingRelayWorker) NotifyQueued() { w.notified.Add(1) }

// TestAdminAPI_DeliverMail_WakesRelayWorker is #327: a redirect or vacation reply
// queued by /admin/mail/deliver must wake the relay worker, as one queued by LMTP
// does, instead of waiting for the worker's next pass (worker_interval).
func TestAdminAPI_DeliverMail_WakesRelayWorker(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rq := &captureRelayQueue{}
	worker := &countingRelayWorker{}
	server, _ := setupHTTPAPIServerWithOptions(t, func(o *adminapi.ServerOptions) {
		o.RelayQueue = rq
		o.RelayWorker = worker
	})
	defer server.Close()

	script := "require [\"vacation\", \"copy\"];\r\nredirect :copy \"elsewhere@example.net\";\r\nvacation \"I am away.\";\r\n"
	marker := fmt.Sprintf("notify-%d", time.Now().UnixNano())
	mailbox := deliverMessageWithScript(t, server, script, marker, func(email string) string {
		return "From: sender@example.com\r\nTo: " + email + "\r\nSubject: wake the relay\r\n" +
			"Message-ID: <" + marker + "@example.com>\r\n\r\nbody\r\n"
	})
	if mailbox != "INBOX" {
		t.Fatalf("redirect :copy must keep the message in INBOX, got %q", mailbox)
	}

	queued := rq.enqueued()
	if len(queued) != 2 {
		t.Fatalf("enqueued %v, want a redirect and a vacation reply", queued)
	}
	if n := worker.notified.Load(); n != int32(len(queued)) {
		t.Errorf("relay worker woken %d times for %d queued messages %v", n, len(queued), queued)
	}
}

// TestAdminAPI_DeliverMail_VacationPersonalMessageCheck is the RFC 5230 §4.5 personal
// message check on /admin/mail/deliver against the credentials table, which issue #487
// answers in one query for all of the original's recipients. The account's own address
// with a +detail counts as the account's; a message that names neither the account nor
// an :addresses entry gets no reply. The second case is the one that fails if the Admin
// API stops wiring the batched ownership lookup: without it the check is skipped and
// every message is answered.
func TestAdminAPI_DeliverMail_VacationPersonalMessageCheck(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rq := &captureRelayQueue{}
	server, _ := setupHTTPAPIServerWithOptions(t, func(o *adminapi.ServerOptions) {
		o.RelayQueue = rq
	})
	defer server.Close()

	script := "require \"vacation\";\r\nvacation \"I am away.\";\r\n"
	for _, tc := range []struct {
		name    string
		to      func(email string) string
		replies int
	}{
		{name: "own address with +detail", to: func(email string) string {
			local, domain, _ := strings.Cut(email, "@")
			return "list@example.net, " + local + "+tag@" + domain
		}, replies: 1},
		{name: "account not named", to: func(string) string {
			return "list@example.net, other@example.net"
		}, replies: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(rq.enqueued())
			marker := fmt.Sprintf("personal-%d", time.Now().UnixNano())
			deliverMessageWithScript(t, server, script, marker, func(email string) string {
				return "From: sender@example.org\r\nTo: " + tc.to(email) + "\r\nSubject: personal?\r\n" +
					"Message-ID: <" + marker + "@example.org>\r\n\r\nbody\r\n"
			})
			replies := 0
			for _, typ := range rq.enqueued()[before:] {
				if typ == "vacation" {
					replies++
				}
			}
			if replies != tc.replies {
				t.Errorf("%d vacation replies, want %d", replies, tc.replies)
			}
		})
	}
}
