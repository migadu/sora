//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/migadu/go-imap/imapclient"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/require"
)

// TestDelivery_SharedNamespaceRootKeepsTheMessageInInbox: the delivery engine (the
// Admin API /deliver path) stores nothing in the shared namespace root ("Shared" for
// "Shared/"), which IMAP SELECT refuses (#1299). Neither a Sieve fileinto of the root
// nor a target mailbox naming it files the message there: it is kept in INBOX, as
// for a target that does not exist. RFC 5228 §4.1: "Implementations MAY place
// restrictions on mailbox names; use of an invalid mailbox name MAY be treated as an
// error or result in delivery to an implementation-defined mailbox". Nor does Sieve
// mailboxexists report the root, which no message can be delivered into (RFC 5490
// §3.1).
func TestDelivery_SharedNamespaceRootKeepsTheMessageInInbox(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	// The account's CREATE of a shared mailbox also creates the root, the account's
	// own, with the creator's rights (insert among them).
	team := fmt.Sprintf("Shared/Team-%d", common.GetTimestamp())
	c, err := imapclient.DialInsecure(imapSrv.Address, nil)
	require.NoError(t, err)
	require.NoError(t, c.Login(account.Email, account.Password).Wait())
	require.NoError(t, c.Create(team, nil).Wait())
	_ = c.Logout()

	dctx := &delivery.DeliveryContext{
		Ctx:             ctx,
		RDB:             rdb,
		Uploader:        common.NewSyncUploaderWithS3(t, rdb, fake, "delivery-host"),
		Hostname:        "delivery-host",
		MetricsLabel:    "http_delivery",
		Logger:          testLogger{t},
		SharedMailboxes: config.SharedMailboxesConfig{Enabled: true, NamespacePrefix: "Shared/"},
	}
	dctx.SieveExecutor = &delivery.StandardSieveExecutor{
		DeliveryCtx:    dctx,
		VacationOracle: &delivery.VacationOracle{RDB: rdb},
	}
	addr, err := server.NewAddress(account.Email)
	require.NoError(t, err)

	cases := []struct {
		name   string
		script string // the active Sieve script; "" delivers to target
		target string
	}{
		{name: "fileinto", script: `require "fileinto"; fileinto "Shared";`},
		{name: "fileinto :create", script: `require ["fileinto", "mailbox"]; fileinto :create "shared";`},
		{name: "mailboxexists", script: `require ["fileinto", "mailbox"]; if mailboxexists "Shared" { fileinto "` + team + `"; }`},
		{name: "target mailbox", target: "Shared"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.script != "" {
				s, err := rdb.CreateScriptWithRetry(ctx, accountID, fmt.Sprintf("root-%d", i), tc.script)
				require.NoError(t, err)
				require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, s.ID, accountID, true))
			}
			marker := fmt.Sprintf("shared-root-%d-%d", i, common.GetTimestamp())
			msg := []byte("From: sender@example.com\r\nTo: " + account.Email +
				"\r\nSubject: " + marker + "\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nbody\r\n")

			result, err := dctx.DeliverMessage(delivery.RecipientInfo{
				AccountID: accountID, Address: &addr, ToAddress: &addr, TargetMailbox: tc.target,
			}, msg)
			require.NoError(t, err, "delivery (result=%+v)", result)
			require.True(t, result.Success)
			require.Equal(t, "INBOX", result.MailboxName)
		})
	}

	require.Equal(t, 0, countLiveInMailbox(t, rdb, accountID, "Shared"), "the namespace root holds no messages")
	require.Equal(t, 0, countLiveInMailbox(t, rdb, accountID, team))
	require.Equal(t, len(cases), countLiveInMailbox(t, rdb, accountID, "INBOX"))
}
