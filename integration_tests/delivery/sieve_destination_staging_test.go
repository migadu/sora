//go:build integration

package delivery_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/require"
)

// Physical resolution can create mailboxes, so evaluating a script or failing to
// stage its body must not carry out its :create action.
func TestDelivery_SieveDestinationResolutionWaitsForStaging(t *testing.T) {
	server, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer server.Close()
	rdb := server.ResilientDB
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	dctx := newSieveDeliveryContext(t, rdb, fake, accountID, `require ["fileinto", "mailbox"]; fileinto :create "MustStayMissing";`)
	recipient := newSelfRecipient(t, accountID, account.Email)
	msg := []byte("From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: staging guard\r\nMessage-ID: <staging-guard@example.com>\r\n\r\n" + strings.Repeat("body", 256))
	_, entity, err := delivery.ParseMessageReader(strings.NewReader(string(msg)))
	require.NoError(t, err)
	_, err = dctx.SieveExecutor.ExecuteSieve(ctx, recipient, entity, msg)
	require.NoError(t, err)
	_, err = rdb.GetMailboxByNameWithRetry(ctx, accountID, "MustStayMissing")
	require.ErrorIs(t, err, consts.ErrMailboxNotFound, "evaluation must not create the target")

	// A file at the account directory blocks staging regardless of the per-attempt
	// Received trace, which changes the final content hash on each delivery.
	accountDir := filepath.Dir(dctx.Uploader.FilePath(strings.Repeat("0", 64), accountID))
	require.NoError(t, os.WriteFile(accountDir, []byte("blocked"), 0600))
	result, err := dctx.DeliverMessage(recipient, msg)
	require.Error(t, err)
	require.False(t, result.Success)
	require.NotEmpty(t, result.ErrorMessage)
	_, err = rdb.GetMailboxByNameWithRetry(ctx, accountID, "MustStayMissing")
	require.ErrorIs(t, err, consts.ErrMailboxNotFound, "staging failure must precede target creation")
}
