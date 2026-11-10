//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureRelayHandler records direct relay sends; it satisfies delivery.RelayHandler.
type captureRelayHandler struct{ captureRelayQueue }

func (h *captureRelayHandler) SendToExternalRelay(from, to string, message []byte) error {
	return h.Enqueue(from, to, "redirect", message)
}

// refusingRelayQueue refuses one address and records the rest.
type refusingRelayQueue struct {
	captureRelayQueue
	refuse string
}

func (q *refusingRelayQueue) Enqueue(from, to, messageType string, messageBytes []byte) error {
	if to == q.refuse {
		return fmt.Errorf("relay queue refused %s", to)
	}
	return q.captureRelayQueue.Enqueue(from, to, messageType, messageBytes)
}

// TestDelivery_SieveMultipleRedirects_PartialFailureKeepsMessage: when one of
// several redirects cannot be handed to the relay, the others still go out and
// the message is kept in INBOX, as it is when a single redirect fails.
func TestDelivery_SieveMultipleRedirects_PartialFailureKeepsMessage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB

	accountID, err := rdb.GetAccountIDByAddressWithRetry(context.Background(), account.Email)
	require.NoError(t, err)

	script := "redirect \"one@example.com\";\r\nredirect \"two@example.org\";\r\nredirect \"three@example.net\";\r\n"
	dctx := newSieveDeliveryContext(t, rdb, fake, accountID, script)
	rq := &refusingRelayQueue{refuse: "two@example.org"}
	dctx.SieveExecutor.(*delivery.StandardSieveExecutor).RelayQueue = rq

	addr, err := server.NewAddress(account.Email)
	require.NoError(t, err)
	sender, err := server.NewAddress("sender@example.com")
	require.NoError(t, err)
	recipient := delivery.RecipientInfo{AccountID: accountID, Address: &addr, ToAddress: &addr, FromAddress: &sender}
	inboxBefore := countLiveInMailbox(t, rdb, accountID, "INBOX")

	msg := []byte(fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nSubject: partial\r\nMessage-ID: <%d@example.com>\r\n\r\nbody\r\n",
		account.Email, time.Now().UnixNano()))
	res, err := dctx.DeliverMessage(recipient, msg)
	require.NoError(t, err)
	require.True(t, res.Success, "delivery must succeed (result=%+v)", res)

	var got []string
	for _, it := range rq.snapshot() {
		got = append(got, it.to)
	}
	assert.Equal(t, []string{"one@example.com", "three@example.net"}, got, "the other addresses must still be relayed")
	assert.Equal(t, 1, countLiveInMailbox(t, rdb, accountID, "INBOX")-inboxBefore, "the message must be kept when a redirect fails")
}

// TestDelivery_SieveMultipleRedirects is issue #230 on the Admin API /deliver path:
// every redirect a script runs must be relayed, through the relay queue and through
// the direct relay handler alike, and the rate limit must be charged for what went out.
func TestDelivery_SieveMultipleRedirects(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	script := strings.Join([]string{
		`require ["copy"];`,
		`if header :contains "subject" "copy" {`,
		`  redirect :copy "one@example.com";`,
		`  redirect :copy "two@example.org";`,
		`  redirect :copy "three@example.net";`,
		`} else {`,
		`  redirect "one@example.com";`,
		`  redirect "two@example.org";`,
		`  redirect "three@example.net";`,
		`}`,
	}, "\r\n") + "\r\n"
	targets := []string{"one@example.com", "three@example.net", "two@example.org"} // sorted
	dctx := newSieveDeliveryContext(t, rdb, fake, accountID, script)
	executor := dctx.SieveExecutor.(*delivery.StandardSieveExecutor)
	executor.RedirectRateLimit = 100
	executor.RedirectRateWindow = time.Hour

	addr, err := server.NewAddress(account.Email)
	require.NoError(t, err)
	sender, err := server.NewAddress("sender@example.com")
	require.NoError(t, err)
	recipient := delivery.RecipientInfo{AccountID: accountID, Address: &addr, ToAddress: &addr, FromAddress: &sender}

	for _, relay := range []string{"queue", "handler"} {
		for _, tc := range []struct {
			subject   string
			wantInbox int
		}{
			{subject: "copy", wantInbox: 1},
			{subject: "plain", wantInbox: 0},
		} {
			t.Run(relay+"/"+tc.subject, func(t *testing.T) {
				_, err := rdb.ExecWithRetry(ctx, "DELETE FROM redirect_log WHERE account_id = $1", accountID)
				require.NoError(t, err)

				var relayed func() []relayItem
				if relay == "queue" {
					rq := &captureRelayQueue{}
					executor.RelayQueue, executor.RelayHandler = rq, nil
					relayed = rq.snapshot
				} else {
					rh := &captureRelayHandler{}
					executor.RelayQueue, executor.RelayHandler = nil, rh
					relayed = rh.snapshot
				}
				inboxBefore := countLiveInMailbox(t, rdb, accountID, "INBOX")

				stamp := time.Now().UnixNano()
				msg := []byte(fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nSubject: %s %d\r\nMessage-ID: <%d@example.com>\r\n\r\nbody\r\n",
					account.Email, tc.subject, stamp, stamp))
				res, err := dctx.DeliverMessage(recipient, msg)
				require.NoError(t, err)
				require.True(t, res.Success, "delivery must succeed (result=%+v)", res)

				var got []string
				for _, it := range relayed() {
					assert.Equal(t, "redirect", it.msgType)
					got = append(got, it.to)
				}
				slices.Sort(got)
				assert.Equal(t, targets, got, "every redirect address must be relayed")
				assert.Equal(t, tc.wantInbox, countLiveInMailbox(t, rdb, accountID, "INBOX")-inboxBefore, "copies added to INBOX")

				var logged int
				require.NoError(t, rdb.QueryRowWithRetry(ctx,
					"SELECT COUNT(*) FROM redirect_log WHERE account_id = $1", accountID).Scan(&logged))
				assert.Equal(t, len(got), logged, "redirects charged against the rate limit vs. relayed")
			})
		}
	}
}
