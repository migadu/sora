//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ageRedirectLog moves every timestamp of the account's redirect_log rows d into the
// past, as if the redirects had been charged d earlier.
func ageRedirectLog(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64, d time.Duration) {
	t.Helper()
	ctx := context.Background()
	rows, err := rdb.QueryWithRetry(ctx, `
		SELECT column_name FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'redirect_log'
		AND data_type = 'timestamp with time zone'`)
	require.NoError(t, err)
	columns, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.NotEmpty(t, columns)
	set := make([]string, len(columns))
	for i, c := range columns {
		set[i] = fmt.Sprintf("%[1]s = %[1]s - make_interval(secs => $2)", c)
	}
	_, err = rdb.ExecWithRetry(ctx,
		"UPDATE redirect_log SET "+strings.Join(set, ", ")+" WHERE account_id = $1", accountID, d.Seconds())
	require.NoError(t, err)
}

// TestDelivery_SieveRedirect_RetentionIndependentOfCleanerNode is #1959: every node with
// an imap, pop3 or lmtp server runs the cleaner, with its own config. A node without an
// lmtp or http_admin_api server knows only the default 1h redirect_rate_window, so with
// grace_period 1h it deleted, after an hour, the redirects a delivering node's 24h window
// still counts, and that node's limit counted only the last hour.
func TestDelivery_SieveRedirect_RetentionIndependentOfCleanerNode(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	imapSrv, account, fake := common.SetupIMAPServerWithRealS3(t)
	defer imapSrv.Close()
	rdb := imapSrv.ResilientDB
	ctx := context.Background()

	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	_, err = rdb.ExecWithRetry(ctx, "DELETE FROM redirect_log WHERE account_id = $1", accountID)
	require.NoError(t, err)

	// The delivering node: a 24h redirect window.
	const window = 24 * time.Hour
	dctx := newSieveDeliveryContext(t, rdb, fake, accountID, "redirect \"one@example.com\";\r\n")
	executor := dctx.SieveExecutor.(*delivery.StandardSieveExecutor)
	executor.RedirectRateLimit = 100
	executor.RedirectRateWindow = window
	executor.RelayQueue = &captureRelayQueue{}

	addr, err := server.NewAddress(account.Email)
	require.NoError(t, err)
	sender, err := server.NewAddress("sender@example.com")
	require.NoError(t, err)
	recipient := delivery.RecipientInfo{AccountID: accountID, Address: &addr, ToAddress: &addr, FromAddress: &sender}
	stamp := time.Now().UnixNano()
	msg := []byte(fmt.Sprintf("From: sender@example.com\r\nTo: %s\r\nSubject: retention %d\r\nMessage-ID: <%d@example.com>\r\n\r\nbody\r\n",
		account.Email, stamp, stamp))
	res, err := dctx.DeliverMessage(recipient, msg)
	require.NoError(t, err)
	require.True(t, res.Success, "delivery must succeed (result=%+v)", res)

	charged := func() int {
		n, err := rdb.CountRedirectsSinceWithRetry(ctx, accountID, window)
		require.NoError(t, err)
		return n
	}
	require.Equal(t, 1, charged(), "the redirect is charged against the 24h window")

	// The cleaner node: grace_period 1h and no lmtp or http_admin_api server, so the
	// redirect retention it computes (cleaner.New) is max(1h, 1h).
	const gracePeriod = time.Hour
	cleanerRetention := max(gracePeriod, (&config.Config{}).LongestRedirectRateWindow())

	ageRedirectLog(t, rdb, accountID, 2*time.Hour)
	_, err = rdb.CleanupOldRedirectsWithRetry(ctx, cleanerRetention)
	require.NoError(t, err)
	assert.Equal(t, 1, charged(),
		"a redirect 2h old is inside the delivering node's 24h window, so the cleaner of a node without that window must keep it")

	ageRedirectLog(t, rdb, accountID, 23*time.Hour)
	_, err = rdb.CleanupOldRedirectsWithRetry(ctx, cleanerRetention)
	require.NoError(t, err)
	var left int
	require.NoError(t, rdb.QueryRowWithRetry(ctx,
		"SELECT COUNT(*) FROM redirect_log WHERE account_id = $1", accountID).Scan(&left))
	assert.Equal(t, 0, left, "a redirect past its 24h window and grace_period is deleted")
}
