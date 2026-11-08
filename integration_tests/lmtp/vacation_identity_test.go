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

func TestLMTP_VacationResponseIdentity(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()
	rdb := srv.ResilientDB
	ctx := context.Background()
	id, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	q := &captureRelayQueue{}
	addr := startTestLMTPServerWithRedirect(t, rdb, q, 10, time.Hour)
	for _, tc := range common.VacationIdentityCases() {
		t.Run(tc.Name, func(t *testing.T) {
			script, err := rdb.CreateScriptWithRetry(ctx, id, fmt.Sprintf("identity-%d", time.Now().UnixNano()), tc.Script)
			require.NoError(t, err)
			require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, script.ID, id, true))
			before := q.count()
			sender := fmt.Sprintf("identity-%d@example.net", time.Now().UnixNano())
			for _, subject := range []string{"first", "second"} {
				raw := "From: " + sender + "\r\nTo: " + account.Email + "\r\nSubject: " + subject + "\r\nMessage-ID: <" + subject + fmt.Sprint(time.Now().UnixNano()) + "@example.net>\r\n\r\nhello\r\n"
				response := deliverLMTPRaw(t, addr, sender, account.Email, raw)
				require.True(t, strings.HasPrefix(response, "250"), "delivery: %s", response)
			}
			require.Equal(t, tc.Replies, q.count()-before, "suppression must distinguish responses, keeping stable raw variable arguments")
		})
	}
}
