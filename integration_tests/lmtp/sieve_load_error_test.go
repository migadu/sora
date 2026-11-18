//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/stretchr/testify/require"
)

// A user script that cannot be read is not the same as no script: delivering with the
// default script alone silently skips the user's fileinto/redirect/vacation/discard.
// The delivery must be deferred (451 4.3.0) so the MTA retries, and nothing stored.
//
// The read is made to fail for this one account only: an updated_at of 'infinity'
// cannot be scanned into a time.Time, so GetActiveScript returns an error other than
// "not found" without touching the schema or any other account.
func TestLMTP_SieveScriptLoadErrorDefersDelivery(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	srv, account := common.SetupLMTPServer(t)
	defer srv.Close()
	rdb, ctx := srv.ResilientDB, context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	stored, err := rdb.CreateScriptWithRetry(ctx, accountID, "unreadable", `require ["fileinto"]; fileinto "Elsewhere";`)
	require.NoError(t, err)
	require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, stored.ID, accountID, true))
	_, err = rdb.GetDatabase().GetWritePool().Exec(ctx,
		`UPDATE sieve_scripts SET updated_at = 'infinity' WHERE id = $1`, stored.ID)
	require.NoError(t, err)
	_, err = rdb.GetActiveScriptWithRetry(ctx, accountID)
	require.Error(t, err, "the active script read must fail for this test to mean anything")

	marker := fmt.Sprintf("sieve-load-error-%d", time.Now().UnixNano())
	raw := "From: sender@example.com\r\nTo: " + account.Email + "\r\nSubject: " + marker +
		"\r\nMessage-ID: <" + marker + "@example.com>\r\n\r\nbody\r\n"
	response := deliverLMTPRaw(t, srv.Address, "sender@example.com", account.Email, raw)
	require.True(t, strings.HasPrefix(response, "451 4.3.0"), "want a temporary failure, got %q", response)
	require.Zero(t, countForAccount(t, rdb, accountID), "nothing may be stored when the user's script could not be read")
}
