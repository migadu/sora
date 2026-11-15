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

// refusingRelayHandler fails the direct relay of one address and records the rest.
type refusingRelayHandler struct {
	captureRelayHandler
	refuse string
}

func (h *refusingRelayHandler) SendToExternalRelay(from, to string, message []byte) error {
	if to == h.refuse {
		return fmt.Errorf("relay refused %s", to)
	}
	return h.captureRelayHandler.SendToExternalRelay(from, to, message)
}

// TestDelivery_SieveRedirect_ChargesOnlyWhatIsRelayed is #327 on the Admin API
// /deliver path: the redirect rate limit counts redirects that were queued or sent.
// A redirect with no relay to take it, or one the relay refused, keeps the message
// in INBOX and must not use up the account's allowance.
func TestDelivery_SieveRedirect_ChargesOnlyWhatIsRelayed(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	script := "redirect \"one@example.com\";\r\nredirect \"two@example.org\";\r\nredirect \"three@example.net\";\r\n"
	dctx := newSieveDeliveryContext(t, rdb, fake, accountID, script)
	executor := dctx.SieveExecutor.(*delivery.StandardSieveExecutor)
	executor.RedirectRateLimit = 100
	executor.RedirectRateWindow = time.Hour

	addr, err := server.NewAddress(account.Email)
	require.NoError(t, err)
	sender, err := server.NewAddress("sender@example.com")
	require.NoError(t, err)
	recipient := delivery.RecipientInfo{AccountID: accountID, Address: &addr, ToAddress: &addr, FromAddress: &sender}

	for _, tc := range []struct {
		name        string
		setup       func()
		wantCharged int
	}{
		{
			name:        "no relay configured",
			setup:       func() { executor.RelayQueue, executor.RelayHandler = nil, nil },
			wantCharged: 0,
		},
		{
			name: "queue refuses one address",
			setup: func() {
				executor.RelayQueue, executor.RelayHandler = &refusingRelayQueue{refuse: "two@example.org"}, nil
			},
			wantCharged: 2,
		},
		{
			name: "relay handler refuses one address",
			setup: func() {
				executor.RelayQueue, executor.RelayHandler = nil, &refusingRelayHandler{refuse: "two@example.org"}
			},
			wantCharged: 2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rdb.ExecWithRetry(ctx, "DELETE FROM redirect_log WHERE account_id = $1", accountID)
			require.NoError(t, err)
			tc.setup()
			inboxBefore := countLiveInMailbox(t, rdb, accountID, "INBOX")

			stamp := time.Now().UnixNano()
			msg := []byte(fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nSubject: charge %d\r\nMessage-ID: <%d@example.com>\r\n\r\nbody\r\n",
				account.Email, stamp, stamp))
			res, err := dctx.DeliverMessage(recipient, msg)
			require.NoError(t, err)
			require.True(t, res.Success, "delivery must succeed (result=%+v)", res)

			assert.Equal(t, 1, countLiveInMailbox(t, rdb, accountID, "INBOX")-inboxBefore, "the message must be kept")
			var charged int
			require.NoError(t, rdb.QueryRowWithRetry(ctx,
				"SELECT COUNT(*) FROM redirect_log WHERE account_id = $1", accountID).Scan(&charged))
			assert.Equal(t, tc.wantCharged, charged, "redirects charged against the rate limit")
		})
	}
}
