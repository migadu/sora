//go:build integration

package delivery_test

import (
	"context"
	"strings"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/require"
)

// TestDelivery_DefaultJunkLookupFailureFailsTheDelivery is the error path of issue
// #987: when the account's \Junk mailbox cannot be looked up, the default script's
// spam filing fails the delivery, to be retried, and is not carried out by the name
// Junk. RFC 8579 §4: "If delivery to the special-use mailbox fails for reasons not
// relating to its existence, the Sieve interpreter MUST NOT subsequently attempt
// delivery in the indicated default mailbox as a fallback." Here a plain folder named
// Junk sits next to the \Junk mailbox (Junk renamed to Spam), so a fallback to the
// name would split the account's spam over two folders. Once the database is back,
// the retry files the message into Spam.
func TestDelivery_DefaultJunkLookupFailureFailsTheDelivery(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	ctx := context.Background()

	account := common.CreateTestAccount(t, rdb)
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	junk, err := rdb.GetMailboxByNameWithRetry(ctx, accountID, consts.MailboxJunk)
	require.NoError(t, err)
	require.NoError(t, rdb.RenameMailboxWithRetry(ctx, junk.ID, accountID, "Spam", nil))
	require.NoError(t, rdb.CreateMailboxWithRetry(ctx, accountID, consts.MailboxJunk, nil))

	owner, err := server.NewAddress(account.Email)
	require.NoError(t, err)
	from, err := server.NewAddress("sender@example.com")
	require.NoError(t, err)
	raw := []byte("From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: spam\r\nX-Spam: Yes\r\n\r\nbody\r\n")
	entity, err := server.ParseMessage(strings.NewReader(string(raw)))
	require.NoError(t, err)
	recipient := delivery.RecipientInfo{AccountID: accountID, Address: &owner, ToAddress: &owner, FromAddress: &from}
	executor := &delivery.StandardSieveExecutor{
		DeliveryCtx: &delivery.DeliveryContext{Ctx: ctx, RDB: rdb, Logger: testLogger{t}, MetricsLabel: "http_delivery"},
	}

	outage.Begin()
	out, err := executor.ExecuteSieve(ctx, recipient, entity, raw)
	outage.End()
	if err == nil {
		t.Fatalf("spam delivered to %q while the \\Junk mailbox could not be looked up, want the delivery to fail", out.MailboxName)
	}

	out, err = executor.ExecuteSieve(ctx, recipient, entity, raw)
	require.NoError(t, err)
	require.Equal(t, "Spam", out.MailboxName, "the retry files the spam into the \\Junk mailbox")
}
