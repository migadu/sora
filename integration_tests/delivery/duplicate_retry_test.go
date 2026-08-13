//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSieveDeliveryContext builds a DeliveryContext wired with the production
// StandardSieveExecutor (the Admin API /deliver wiring) and activates script for the
// account.
func newSieveDeliveryContext(t *testing.T, rdb *resilient.ResilientDatabase, fake *common.FakeS3, accountID int64, script string) *delivery.DeliveryContext {
	t.Helper()
	ctx := context.Background()

	s, err := rdb.CreateScriptWithRetry(ctx, accountID, "active", script)
	require.NoError(t, err)
	require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, s.ID, accountID, true))

	active, err := rdb.GetActiveScriptWithRetry(ctx, accountID)
	require.NoError(t, err)
	require.Equal(t, script, active.Script, "the script under test must be the active one")

	dctx := &delivery.DeliveryContext{
		Ctx:          ctx,
		RDB:          rdb,
		Uploader:     common.NewSyncUploaderWithS3(t, rdb, fake, "delivery-host"),
		Hostname:     "delivery-host",
		MetricsLabel: "http_delivery",
		Logger:       testLogger{t},
	}
	dctx.SieveExecutor = &delivery.StandardSieveExecutor{
		DeliveryCtx:    dctx,
		VacationOracle: &delivery.VacationOracle{RDB: rdb},
	}
	return dctx
}

// TestDelivery_DuplicateRetry_FileintoCopy_IsAccepted is the regression guard for the
// Admin API duplicate-absorption legs.
//
// Scenario: an Admin API client POSTs a message, the delivery commits but the HTTP
// response is lost, and the client retries the identical bytes. The delivery_hash dedup
// in db/append.go fires on the retry. DeliverMessage's own insert absorbs that as an
// accepted delivery, but the SIEVE `fileinto :copy` leg goes through
// DeliveryContext.SaveMessageToMailbox, whose ErrMessageExists used to propagate out of
// ExecuteSieve as a Sieve execution error — so the API reported a FAILED delivery for a
// message that is in the mailbox, and every retry failed the same way.
func TestDelivery_DuplicateRetry_FileintoCopy_IsAccepted(t *testing.T) {
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

	marker := fmt.Sprintf("dup-fileinto-copy-%d", common.GetTimestamp())
	msgBytes := []byte("From: sender@example.com\r\nTo: " + account.Email +
		"\r\nSubject: " + marker + "\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nbody\r\n")

	first, err := dctx.DeliverMessage(recipient, msgBytes)
	require.NoError(t, err, "first delivery must succeed (result=%+v)", first)
	require.True(t, first.Success)
	require.Equal(t, 1, countLiveInMailbox(t, rdb, accountID, "Archive"),
		"fileinto :copy must file the message into Archive")
	require.Equal(t, 1, countLiveInMailbox(t, rdb, accountID, "INBOX"),
		"fileinto :copy must also keep a copy in INBOX")

	// The retry of the lost-acknowledgement submission: identical bytes, new attempt.
	second, err := dctx.DeliverMessage(recipient, msgBytes)
	require.NoError(t, err,
		"retry of an already-delivered message must not error out of the fileinto :copy leg (result=%+v)", second)
	assert.True(t, second.Success,
		"a duplicate retry is an accepted delivery on every leg; the Admin API reported Accepted=false with error %q", second.ErrorMessage)
	assert.Empty(t, second.ErrorMessage)

	assert.Equal(t, 1, countLiveInMailbox(t, rdb, accountID, "Archive"),
		"the retry must not add a second copy to Archive")
	assert.Equal(t, 1, countLiveInMailbox(t, rdb, accountID, "INBOX"),
		"the retry must not add a second copy to INBOX")
}

// TestDelivery_DuplicateRetry_ReportsResolvedMailboxAndUID asserts that the absorbed
// duplicate reports where the message actually is. DeliverMessage returned Success=true
// with MessageUID=0 and MailboxName left at its INBOX default, so the Admin API logged
// "delivered successfully to mailbox=INBOX uid=0" for a message filed into Archive.
// InsertMessage returns the existing row's UID alongside consts.ErrMessageExists.
func TestDelivery_DuplicateRetry_ReportsResolvedMailboxAndUID(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	dctx := newSieveDeliveryContext(t, rdb, fake, accountID,
		"require [\"fileinto\"];\r\nfileinto \"Archive\";\r\n")

	addr, err := server.NewAddress(account.Email)
	require.NoError(t, err)
	recipient := delivery.RecipientInfo{AccountID: accountID, Address: &addr, ToAddress: &addr}

	marker := fmt.Sprintf("dup-fileinto-%d", common.GetTimestamp())
	msgBytes := []byte("From: sender@example.com\r\nTo: " + account.Email +
		"\r\nSubject: " + marker + "\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nbody\r\n")

	first, err := dctx.DeliverMessage(recipient, msgBytes)
	require.NoError(t, err, "first delivery must succeed (result=%+v)", first)
	require.True(t, first.Success)
	require.Equal(t, "Archive", first.MailboxName)
	require.NotZero(t, first.MessageUID)

	second, err := dctx.DeliverMessage(recipient, msgBytes)
	require.NoError(t, err)
	require.True(t, second.Success)

	assert.Equal(t, first.MailboxName, second.MailboxName,
		"an absorbed duplicate must report the mailbox the message is in, not the INBOX default")
	assert.Equal(t, first.MessageUID, second.MessageUID,
		"an absorbed duplicate must report the existing message's UID, not 0")
}
