//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDelivery_SieveRedirectRelayedOnlyAfterStore is issue #452 on the Admin API
// /deliver path: a redirect is handed to the relay only once the message is stored.
// A delivery whose store fails is reported as failed and retried by the caller; had
// the redirect been relayed first, every retry would relay it again.
func TestDelivery_SieveRedirectRelayedOnlyAfterStore(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	dctx := newSieveDeliveryContext(t, rdb, fake, accountID,
		"require [\"copy\"];\r\nredirect :copy \"other@example.org\";\r\n")
	rq := &captureRelayQueue{}
	dctx.SieveExecutor.(*delivery.StandardSieveExecutor).RelayQueue = rq

	addr, err := server.NewAddress(account.Email)
	require.NoError(t, err)
	sender, err := server.NewAddress("sender@example.com")
	require.NoError(t, err)
	recipient := delivery.RecipientInfo{AccountID: accountID, Address: &addr, ToAddress: &addr, FromAddress: &sender}
	msg := []byte(fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nSubject: redirect after store\r\nMessage-ID: <%d@example.com>\r\n\r\nbody\r\n",
		account.Email, time.Now().UnixNano()))

	// First attempt: INBOX is gone, so storing the :copy fails.
	_, err = rdb.ExecWithRetry(ctx,
		"UPDATE mailboxes SET deleted_at = NOW() WHERE account_id = $1 AND LOWER(name) = 'inbox' AND deleted_at IS NULL", accountID)
	require.NoError(t, err)
	res, err := dctx.DeliverMessage(recipient, msg)
	require.Error(t, err, "a delivery that cannot store the message must fail (result=%+v)", res)
	assert.Empty(t, rq.snapshot(), "a delivery whose store failed must not have relayed the message")

	// The caller's retry, once INBOX is back: stored, and relayed once.
	require.NoError(t, rdb.CreateDefaultMailboxesWithRetry(ctx, accountID))
	res, err = dctx.DeliverMessage(recipient, msg)
	require.NoError(t, err)
	require.True(t, res.Success, "retry must succeed (result=%+v)", res)
	assert.Equal(t, []relayItem{{to: "other@example.org", msgType: "redirect"}}, rq.snapshot(),
		"the message must be relayed once over both attempts")
	assert.Equal(t, 1, countLiveInMailbox(t, rdb, accountID, "INBOX"), "INBOX copies after the retry")
}
