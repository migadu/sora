//go:build integration

package delivery_test

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-message"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/delivery"
	"github.com/migadu/sora/server/sieveengine"
	"github.com/stretchr/testify/require"
)

// pendingVacation is one independently evaluated delivery, including the real DB
// oracle's deferred handoff operation. Preparing all deliveries before any handoff
// deterministically puts them past the evaluation-time allowance check together.
type pendingVacation struct {
	accountID int64
	reply     sieveengine.VacationReply
	sender    server.Address
	recipient server.Address
	original  *message.Entity
	queue     *captureRelayQueue
}

func prepareVacation(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64, sender, handle string, queue *captureRelayQueue) pendingVacation {
	t.Helper()
	const recipient = "recipient@example.com"
	script := fmt.Sprintf(`require "vacation"; vacation :days 7 :handle %q "Away";`, handle)
	oracle := &delivery.VacationOracle{RDB: rdb}
	executor, err := sieveengine.NewSieveExecutorWithOracleAndExtensions(script, accountID, oracle, oracle, 0, time.Hour, 0, []string{"vacation"})
	require.NoError(t, err)
	raw := []byte("From: " + sender + "\r\nTo: " + recipient + "\r\nSubject: Hello\r\n\r\nMessage body.\r\n")
	result, err := executor.Evaluate(context.Background(), sieveengine.Context{
		EnvelopeFrom: sender, EnvelopeTo: recipient, Message: raw,
		Header: map[string][]string{"From": {sender}, "To": {recipient}, "Subject": {"Hello"}},
	})
	require.NoError(t, err)
	require.NotNil(t, result.Vacation, "the evaluation must precede the suppression claim")
	from, err := server.NewAddress(sender)
	require.NoError(t, err)
	to, err := server.NewAddress(recipient)
	require.NoError(t, err)
	original, err := message.Read(bytes.NewReader(raw))
	require.NoError(t, err)
	return pendingVacation{accountID: accountID, reply: *result.Vacation, sender: from, recipient: to, original: original, queue: queue}
}

func (p pendingVacation) handoff(ctx context.Context) error {
	// Each delivery has its own handler, as sessions on separate backend processes
	// do. Only the PostgreSQL history and the observing relay queue are shared.
	handler := &delivery.StandardVacationHandler{Hostname: "test", RelayQueue: p.queue}
	return handler.HandleVacationResponse(ctx, p.accountID, p.reply, &p.sender, &p.recipient, p.original)
}

func vacationClaimAccount(t *testing.T, rdb *resilient.ResilientDatabase) int64 {
	t.Helper()
	var id int64
	require.NoError(t, rdb.QueryRowWithRetry(context.Background(), `INSERT INTO accounts DEFAULT VALUES RETURNING id`).Scan(&id))
	t.Cleanup(func() {
		_, err := rdb.ExecWithRetry(context.Background(), `DELETE FROM accounts WHERE id = $1`, id)
		require.NoError(t, err)
	})
	return id
}

func vacationClaimRecords(t *testing.T, rdb *resilient.ResilientDatabase, accountID int64) int {
	t.Helper()
	var records int
	require.NoError(t, rdb.QueryRowWithRetry(context.Background(), `SELECT count(*) FROM vacation_responses WHERE account_id = $1`, accountID).Scan(&records))
	return records
}

func TestVacationClaim_OverlappingEvaluations(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	id := vacationClaimAccount(t, rdb)
	queue := &captureRelayQueue{}
	a := prepareVacation(t, rdb, id, "sender@example.net", "same-response", queue)
	b := prepareVacation(t, rdb, id, "sender@example.net", "same-response", queue)
	require.NoError(t, a.handoff(context.Background()))
	require.NoError(t, b.handoff(context.Background()), "losing the claim is ordinary suppression, not a delivery error")
	require.Len(t, queue.snapshot(), 1, "two deliveries already past the allowance check must still send only one reply")
	require.Equal(t, 1, vacationClaimRecords(t, rdb, id), "the loser must not add another history record")
}

func TestVacationClaim_ConcurrentSessionsAndIndependentKeys(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	accountA, accountB := vacationClaimAccount(t, rdb), vacationClaimAccount(t, rdb)
	keys := []struct {
		accountID      int64
		sender, handle string
		queue          *captureRelayQueue
	}{
		{accountA, "sender@example.net", "response-a", &captureRelayQueue{}},
		{accountA, "other@example.net", "response-a", &captureRelayQueue{}},
		{accountA, "sender@example.net", "response-b", &captureRelayQueue{}},
		{accountB, "sender@example.net", "response-a", &captureRelayQueue{}},
	}
	var pending []pendingVacation
	for _, key := range keys {
		for range 8 {
			pending = append(pending, prepareVacation(t, rdb, key.accountID, key.sender, key.handle, key.queue))
		}
	}
	start := make(chan struct{})
	errs := make(chan error, len(pending))
	var wg sync.WaitGroup
	for _, session := range pending {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- session.handoff(context.Background())
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	for _, key := range keys {
		require.Len(t, key.queue.snapshot(), 1, "account=%d sender=%s handle=%s", key.accountID, key.sender, key.handle)
	}
	require.Equal(t, 3, vacationClaimRecords(t, rdb, accountA))
	require.Equal(t, 1, vacationClaimRecords(t, rdb, accountB))
}

func TestVacationClaim_SuppressionAndDatabaseFailure(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	id := vacationClaimAccount(t, rdb)
	queue := &captureRelayQueue{}
	suppressed := prepareVacation(t, rdb, id, "sender@example.net", "same-response", queue)
	suppressed.original.Header.Set("Auto-Submitted", "auto-generated")
	require.NoError(t, suppressed.handoff(context.Background()))
	require.Empty(t, queue.snapshot())
	require.Zero(t, vacationClaimRecords(t, rdb, id), "message suppression must not consume the claim")

	failed := prepareVacation(t, rdb, id, "sender@example.net", "same-response", queue)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.Error(t, failed.handoff(ctx), "an unavailable claim must fail closed")
	require.Empty(t, queue.snapshot())
	require.Zero(t, vacationClaimRecords(t, rdb, id))

	next := prepareVacation(t, rdb, id, "sender@example.net", "same-response", queue)
	require.NoError(t, next.handoff(context.Background()))
	require.Len(t, queue.snapshot(), 1)
	require.Equal(t, 1, vacationClaimRecords(t, rdb, id))
}
