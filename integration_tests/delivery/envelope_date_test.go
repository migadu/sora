//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDelivery_AbsentDateHeaderEnvelopeIsNIL: a message delivered without a Date: header
// has a NIL ENVELOPE date (RFC 9051 section 7.5.2) and sorts by its INTERNALDATE (RFC 5256
// section 2.2), both in INBOX (DeliverMessage) and in the mailbox a Sieve fileinto :copy
// files it into (SaveMessageToMailbox). Before the fix the delivery time was stored and
// reported as the message's Date: header.
func TestDelivery_AbsentDateHeaderEnvelopeIsNIL(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	dctx := newSieveDeliveryContext(t, rdb, fake, accountID,
		"require [\"fileinto\", \"copy\"];\r\nfileinto :copy \"Archive\";\r\n")

	addr, err := server.NewAddress(account.Email)
	require.NoError(t, err)
	recipient := delivery.RecipientInfo{AccountID: accountID, Address: &addr, ToAddress: &addr}

	marker := fmt.Sprintf("delivery-envdate-%d", common.GetTimestamp())
	res, err := dctx.DeliverMessage(recipient, []byte("From: sender@example.com\r\nTo: "+account.Email+
		"\r\nSubject: "+marker+"\r\nMessage-ID: <"+marker+"@example.com>\r\n\r\nbody\r\n"))
	require.NoError(t, err)
	require.True(t, res.Success, "delivery failed: %+v", res)

	for _, mailbox := range []string{"INBOX", "Archive"} {
		var uid, mailboxID int64
		var sentDate, internalDate time.Time
		require.NoError(t, rdb.QueryRowWithRetry(ctx, `
			SELECT m.uid, m.mailbox_id, m.sent_date, m.internal_date
			FROM messages m JOIN mailboxes mb ON mb.id = m.mailbox_id
			WHERE mb.account_id = $1 AND mb.name = $2 AND m.subject = $3 AND m.expunged_at IS NULL
		`, accountID, mailbox, marker).Scan(&uid, &mailboxID, &sentDate, &internalDate))

		assert.True(t, sentDate.Equal(internalDate), "%s: stored sent_date %v, want the INTERNALDATE %v", mailbox, sentDate, internalDate)

		env, err := rdb.GetDatabase().GetMessageEnvelope(ctx, imap.UID(uid), mailboxID)
		require.NoError(t, err)
		assert.True(t, env.Date.IsZero(), "%s: envelope date %v, want NIL", mailbox, env.Date)
	}
}
