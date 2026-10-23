//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureRelayQueue records what the delivery hands to the relay; it satisfies
// delivery.RelayQueue.
type captureRelayQueue struct {
	mu    sync.Mutex
	items []relayItem
}

type relayItem struct{ to, msgType string }

func (q *captureRelayQueue) Enqueue(from, to, messageType string, messageBytes []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, relayItem{to: to, msgType: messageType})
	return nil
}

func (q *captureRelayQueue) snapshot() []relayItem {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]relayItem(nil), q.items...)
}

// TestDelivery_SieveVacation_AlongsideOtherActions is issue #113 on the Admin API
// /deliver path, which evaluates Sieve apart from LMTP: a script holding a vacation
// and the user's filters must reply to every message, whatever the filters did with
// it (RFC 5230 §4.7), and what the filters did must still happen.
func TestDelivery_SieveVacation_AlongsideOtherActions(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	_, err = rdb.GetOrCreateMailboxByNameWithRetry(ctx, accountID, "Invoices")
	require.NoError(t, err)

	const redirectTarget = "elsewhere@example.net"
	script := strings.Join([]string{
		`require ["fileinto", "vacation"];`,
		`vacation :days 1 :subject "Away" "I am away until Monday.";`,
		`if header :contains "subject" "invoice" { fileinto "Invoices"; }`,
		`elsif header :contains "subject" "forward" { redirect "` + redirectTarget + `"; }`,
		`elsif header :contains "subject" "drop" { discard; }`,
	}, "\r\n") + "\r\n"
	dctx := newSieveDeliveryContext(t, rdb, fake, accountID, script)

	// Wired as the Admin API wires it: replies and redirects go through the relay queue.
	rq := &captureRelayQueue{}
	executor := dctx.SieveExecutor.(*delivery.StandardSieveExecutor)
	executor.RelayQueue = rq
	executor.VacationHandler = &delivery.StandardVacationHandler{
		Hostname:       "delivery-host",
		RelayQueue:     rq,
		Logger:         testLogger{t},
		IsOwnedAddress: rdb.IsAddressOwnedByAccountWithRetry,
	}

	addr, err := server.NewAddress(account.Email)
	require.NoError(t, err)

	cases := []struct {
		name     string
		subject  string
		inbox    int // copies the message adds to INBOX
		invoices int // copies the message adds to Invoices
		relayed  bool
	}{
		{name: "keep", subject: "hello", inbox: 1},
		{name: "fileinto", subject: "invoice 42", invoices: 1},
		{name: "redirect", subject: "forward this", relayed: true},
		{name: "discard", subject: "drop this"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A sender of its own: the :days window an earlier case opened is per sender.
			stamp := time.Now().UnixNano()
			sender, err := server.NewAddress(fmt.Sprintf("sender-%d@example.com", stamp))
			require.NoError(t, err)
			recipient := delivery.RecipientInfo{AccountID: accountID, Address: &addr, ToAddress: &addr, FromAddress: &sender}

			inboxBefore := countLiveInMailbox(t, rdb, accountID, "INBOX")
			invoicesBefore := countLiveInMailbox(t, rdb, accountID, "Invoices")
			relayedBefore := len(rq.snapshot())

			msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s %d\r\nMessage-ID: <%d@example.com>\r\n\r\nbody\r\n",
				sender.FullAddress(), account.Email, tc.subject, stamp, stamp))
			res, err := dctx.DeliverMessage(recipient, msg)
			require.NoError(t, err)
			require.True(t, res.Success, "delivery must succeed (result=%+v)", res)

			var replies, redirects int
			for _, it := range rq.snapshot()[relayedBefore:] {
				switch {
				case it.msgType == "vacation" && it.to == sender.FullAddress():
					replies++
				case it.msgType == "redirect" && it.to == redirectTarget:
					redirects++
				default:
					t.Errorf("unexpected relay item %+v", it)
				}
			}
			assert.Equal(t, 1, replies, "the sender must get exactly one vacation reply")
			wantRedirects := 0
			if tc.relayed {
				wantRedirects = 1
			}
			assert.Equal(t, wantRedirects, redirects, "redirects")

			assert.Equal(t, tc.inbox, countLiveInMailbox(t, rdb, accountID, "INBOX")-inboxBefore, "copies added to INBOX")
			assert.Equal(t, tc.invoices, countLiveInMailbox(t, rdb, accountID, "Invoices")-invoicesBefore, "copies added to Invoices")
		})
	}
}
