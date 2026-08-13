//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/stretchr/testify/require"
)

// The Admin API builds a fresh StandardSieveExecutor per message, so the compiled-script
// cache backing it has to be process-wide to ever see a second hit. These tests pin both
// halves of that: the compile is reused across deliveries, and every write to the script
// row reaches the next delivery.
//
// A cache hit and a cache miss deliver identically - that is the whole point of keying the
// cache on the script text - so "was it recompiled?" is read off the cache's own hit/miss
// counters rather than probed behaviourally.

const (
	sieveFileintoArchive = "require [\"fileinto\"];\r\nfileinto \"Archive\";\r\n"
	sieveFileintoJunk    = "require [\"fileinto\"];\r\nfileinto \"Junk\";\r\n"
	sieveFileintoDrafts  = "require [\"fileinto\"];\r\nfileinto \"Drafts\";\r\n"
)

func TestDelivery_SieveScriptCompiledOncePerScriptVersion(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	// A script unique to this run, so a parallel test's script cannot supply the entry.
	script := fmt.Sprintf("require [\"fileinto\"];\r\n# %d\r\nfileinto \"Archive\";\r\n", common.GetTimestamp())
	dctx := newSieveDeliveryContext(t, rdb, fake, accountID, script)
	recipient := newSelfRecipient(t, accountID, account.Email)

	_, missesBefore := sieveengine.SharedScriptCache().Stats()

	const deliveries = 5
	for i := 1; i <= deliveries; i++ {
		require.Equalf(t, consts.MailboxArchive,
			deliverSieveProbe(t, dctx, recipient, account.Email, fmt.Sprintf("cached-%d", i)).MailboxName,
			"delivery %d did not run the active script", i)
	}

	_, missesAfter := sieveengine.SharedScriptCache().Stats()
	require.Equal(t, uint64(1), missesAfter-missesBefore,
		"%d deliveries of one script version caused %d compiles: the delivery path is parsing "+
			"the user's Sieve again for every message", deliveries, missesAfter-missesBefore)
}

func TestDelivery_SieveScriptRecompiledAfterUserEdit(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	dctx := newSieveDeliveryContext(t, rdb, fake, accountID, sieveFileintoArchive)
	recipient := newSelfRecipient(t, accountID, account.Email)

	require.Equal(t, consts.MailboxArchive,
		deliverSieveProbe(t, dctx, recipient, account.Email, "before-edit").MailboxName,
		"precondition: the active script must file into Archive")

	// The edit path a user actually reaches, not a hand-written UPDATE: whatever it does
	// to updated_at is what the cache has to notice.
	active, err := rdb.GetActiveScriptWithRetry(ctx, accountID)
	require.NoError(t, err)
	_, err = rdb.UpdateScriptWithRetry(ctx, active.ID, accountID, active.Name, sieveFileintoJunk)
	require.NoError(t, err)

	res := deliverSieveProbe(t, dctx, recipient, account.Email, "after-edit")
	require.Equal(t, consts.MailboxJunk, res.MailboxName,
		"an edited script was not recompiled: a cached compile kept filtering mail with the rules "+
			"the user just replaced")
}

// TestDelivery_SieveCacheFollowsEveryScriptMutation walks every write in
// db/sieve_scripts.go and checks the next delivery reflects it. The cache is keyed on the
// script text, so a content change cannot survive it by construction - but that only
// holds if the delivery path re-reads the active script per message and compiles the text
// it read, which is what this exercises end to end.
func TestDelivery_SieveCacheFollowsEveryScriptMutation(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)

	// CreateScript + SetScriptActive(true): the account's first script takes effect.
	dctx := newSieveDeliveryContext(t, rdb, fake, accountID, sieveFileintoArchive)
	recipient := newSelfRecipient(t, accountID, account.Email)
	first, err := rdb.GetActiveScriptWithRetry(ctx, accountID)
	require.NoError(t, err)

	filesInto := func(marker, want string) {
		t.Helper()
		require.Equal(t, want, deliverSieveProbe(t, dctx, recipient, account.Email, marker).MailboxName,
			"delivery after %q went to the wrong mailbox", marker)
	}
	filesInto("created-and-activated", consts.MailboxArchive)

	// UpdateScript: new body, same script.
	_, err = rdb.UpdateScriptWithRetry(ctx, first.ID, accountID, first.Name, sieveFileintoJunk)
	require.NoError(t, err)
	filesInto("updated", consts.MailboxJunk)

	// RenameScript: touches the row but not the rules, and must not deactivate it.
	require.NoError(t, rdb.RenameScriptWithRetry(ctx, accountID, first.Name, first.Name+"-renamed"))
	filesInto("renamed", consts.MailboxJunk)

	// CreateScript: a second script is created inactive and must not take over.
	second, err := rdb.CreateScriptWithRetry(ctx, accountID, "second", sieveFileintoDrafts)
	require.NoError(t, err)
	filesInto("second-created-inactive", consts.MailboxJunk)

	// SetScriptActive(true): switching scripts switches the rules.
	require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, second.ID, accountID, true))
	filesInto("second-activated", consts.MailboxDrafts)

	// SetScriptActive(false): no active script leaves delivery at INBOX.
	require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, second.ID, accountID, false))
	filesInto("second-deactivated", consts.MailboxInbox)

	// DeactivateAllScripts.
	require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, second.ID, accountID, true))
	filesInto("second-reactivated", consts.MailboxDrafts)
	require.NoError(t, rdb.DeactivateAllScriptsWithRetry(ctx, accountID))
	filesInto("all-deactivated", consts.MailboxInbox)

	// DeleteScript: the active script disappearing leaves delivery at INBOX.
	require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, first.ID, accountID, true))
	filesInto("first-reactivated", consts.MailboxJunk)
	require.NoError(t, rdb.DeleteScriptByIDWithRetry(ctx, first.ID, accountID))
	filesInto("first-deleted", consts.MailboxInbox)
}

func newSelfRecipient(t *testing.T, accountID int64, email string) delivery.RecipientInfo {
	t.Helper()
	addr, err := server.NewAddress(email)
	require.NoError(t, err)
	return delivery.RecipientInfo{AccountID: accountID, Address: &addr, ToAddress: &addr}
}

// deliverSieveProbe delivers one message whose bytes are unique to marker, keeping the
// delivery_hash dedup in db/append.go out of the way.
func deliverSieveProbe(t *testing.T, dctx *delivery.DeliveryContext, recipient delivery.RecipientInfo, email, marker string) *delivery.DeliveryResult {
	t.Helper()

	id := fmt.Sprintf("sieve-cache-%s-%d", marker, common.GetTimestamp())
	msg := []byte("From: sender@example.com\r\nTo: " + email +
		"\r\nSubject: " + id + "\r\nMessage-ID: <" + id + "@example.com>\r\n\r\nbody\r\n")

	res, err := dctx.DeliverMessage(recipient, msg)
	require.NoError(t, err, "delivery %q failed (result=%+v)", marker, res)
	require.True(t, res.Success, "delivery %q was not accepted (result=%+v)", marker, res)
	return res
}
