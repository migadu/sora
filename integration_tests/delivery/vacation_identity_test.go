//go:build integration

package delivery_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/stretchr/testify/require"
)

func TestDelivery_VacationResponseIdentity(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	srv, account := common.SetupIMAPServer(t)
	defer srv.Close()
	rdb := srv.ResilientDB
	ctx := context.Background()
	id, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	require.NoError(t, err)
	owner, err := server.NewAddress(account.Email)
	require.NoError(t, err)
	for _, tc := range common.VacationIdentityCases() {
		t.Run(tc.Name, func(t *testing.T) {
			script, err := rdb.CreateScriptWithRetry(ctx, id, fmt.Sprintf("identity-%d", time.Now().UnixNano()), tc.Script)
			require.NoError(t, err)
			require.NoError(t, rdb.SetScriptActiveWithRetry(ctx, script.ID, id, true))
			q := &captureRelayQueue{}
			executor := &delivery.StandardSieveExecutor{
				DeliveryCtx:     &delivery.DeliveryContext{Ctx: ctx, RDB: rdb, Logger: testLogger{t}, MetricsLabel: "http_delivery"},
				VacationOracle:  &delivery.VacationOracle{RDB: rdb},
				VacationHandler: &delivery.StandardVacationHandler{Hostname: "m", RelayQueue: q, IsOwnedAddress: rdb.IsAddressOwnedByAccountWithRetry},
			}
			from, err := server.NewAddress(fmt.Sprintf("identity-%d@example.net", time.Now().UnixNano()))
			require.NoError(t, err)
			for _, subject := range []string{"first", "second"} {
				raw := []byte("From: " + from.FullAddress() + "\r\nTo: " + account.Email + "\r\nSubject: " + subject + "\r\n\r\nhello\r\n")
				entity, err := server.ParseMessage(strings.NewReader(string(raw)))
				require.NoError(t, err)
				out, err := executor.ExecuteSieve(ctx, delivery.RecipientInfo{AccountID: id, Address: &owner, ToAddress: &owner, FromAddress: &from}, entity, raw)
				require.NoError(t, err)
				require.False(t, out.Discarded, "the vacation action must not discard the message")
			}
			require.Len(t, q.snapshot(), tc.Replies, "suppression must distinguish responses, keeping stable raw variable arguments")
		})
	}
}
