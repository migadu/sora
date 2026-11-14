//go:build integration

package lmtp_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
	"github.com/migadu/sora/server/uploader"
	"github.com/migadu/sora/storage"
)

// TestLMTP_StagingLimitRefusesBeforeSieve is issue #293: a delivery refused with 452
// because [uploader] max_staging_size would be exceeded must have had no Sieve side
// effect. The sending MTA retries it, and the script runs again then; a vacation reply
// sent and redirects charged on a refused attempt are sent and charged once per
// attempt. The Admin API path checks the limit before Sieve for that reason.
func TestLMTP_StagingLimitRefusesBeforeSieve(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	ctx := context.Background()
	accountID, err := rdb.GetAccountIDByAddressWithRetry(ctx, account.Email)
	if err != nil {
		t.Fatalf("account id: %v", err)
	}
	if _, err := rdb.ExecWithRetry(ctx, "DELETE FROM vacation_responses WHERE account_id = $1", accountID); err != nil {
		t.Fatalf("clear vacation_responses: %v", err)
	}
	setActiveSieveScript(t, rdb, accountID, strings.Join([]string{
		`require ["vacation"];`,
		`vacation :days 1 "I am away.";`,
		`redirect "other@example.org";`,
	}, "\r\n")+"\r\n")

	// Any message is larger than a 10-byte staging limit.
	up, err := uploader.NewWithS3Interface(
		t.TempDir(), 10, 2, 3, time.Second, 10, "test-instance", rdb,
		&common.NoopUploaderS3{}, &common.NoopUploaderCache{}, make(chan error, 1),
	)
	if err != nil {
		t.Fatalf("uploader: %v", err)
	}
	rq := &captureRelayQueue{}
	addr := common.GetRandomAddress(t)
	srv, err := lmtpserver.New(ctx, "test-lmtp-staging", "localhost", addr, &storage.S3Storage{}, rdb, up,
		lmtpserver.LMTPServerOptions{RelayQueue: rq, RedirectRateLimit: 10, RedirectRateWindow: time.Hour})
	if err != nil {
		t.Fatalf("lmtp new: %v", err)
	}
	t.Cleanup(func() { srv.Close() })
	errChan := make(chan error, 1)
	go srv.Start(errChan)
	waitForLMTPListener(t, addr, errChan)

	const sender = "sender@example.com"
	msg := strings.Join([]string{
		"From: " + sender,
		"To: " + account.Email,
		"Subject: staging limit",
		fmt.Sprintf("Message-ID: <%d@example.com>", time.Now().UnixNano()),
		"",
		"This message is larger than the staging limit.",
	}, "\r\n")
	if resp := deliverLMTPRaw(t, addr, sender, account.Email, msg); !strings.HasPrefix(resp, "452") {
		t.Fatalf("want 452 for a delivery over the staging limit, got %s", resp)
	}

	for _, it := range rq.items() {
		t.Errorf("a refused delivery handed %s to the relay (to %s)", it.msgType, it.to)
	}
	if n := countRedirectLog(t, rdb, accountID); n != 0 {
		t.Errorf("a refused delivery charged %d redirects to the rate limit", n)
	}
	var replies int
	if err := rdb.QueryRowWithRetry(ctx, "SELECT COUNT(*) FROM vacation_responses WHERE account_id = $1", accountID).Scan(&replies); err != nil {
		t.Fatalf("count vacation_responses: %v", err)
	}
	if replies != 0 {
		t.Errorf("a refused delivery consumed the vacation period (%d rows)", replies)
	}
}
