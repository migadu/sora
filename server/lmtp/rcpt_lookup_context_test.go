//go:build integration

package lmtp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

// The account lookup at RCPT is answered like the later RCPT steps (#1909): the RCPT
// timeout running out is "Recipient validation timed out", and the session's context
// ending (server shutdown, client disconnect) is 421 4.2.1, not the generic 451 of a
// database failure.
func TestRcptAccountLookupTimeoutAndShutdown(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Stall the lookup: it reads credentials, which this transaction holds locked.
	stall := func(t *testing.T) {
		t.Helper()
		tx, err := rdb.GetOperationalDatabase().GetWritePool().Begin(context.Background())
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
		if _, err := tx.Exec(context.Background(), "LOCK TABLE credentials IN ACCESS EXCLUSIVE MODE"); err != nil {
			t.Fatalf("lock credentials: %v", err)
		}
	}

	rcptErr := func(t *testing.T, err error) *smtp.SMTPError {
		t.Helper()
		var smtpErr *smtp.SMTPError
		if !errors.As(err, &smtpErr) {
			t.Fatalf("RCPT = %v, want an SMTP reply", err)
		}
		return smtpErr
	}

	t.Run("timeout", func(t *testing.T) {
		stall(t)
		got := rcptErr(t, lmtpserver.RcptForTest(context.Background(), rdb, 300*time.Millisecond, account.Email))
		if got.Code != 451 || got.EnhancedCode != (smtp.EnhancedCode{4, 4, 3}) ||
			got.Message != "Recipient validation timed out, please try again later" {
			t.Fatalf("RCPT = %d %v %q, want 451 4.4.3 Recipient validation timed out", got.Code, got.EnhancedCode, got.Message)
		}
	})

	t.Run("shutdown", func(t *testing.T) {
		stall(t)
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(300*time.Millisecond, cancel)
		defer cancel()
		got := rcptErr(t, lmtpserver.RcptForTest(ctx, rdb, 10*time.Second, account.Email))
		if got.Code != 421 || got.EnhancedCode != (smtp.EnhancedCode{4, 2, 1}) {
			t.Fatalf("RCPT = %d %v %q, want 421 4.2.1 service shutting down", got.Code, got.EnhancedCode, got.Message)
		}
	})
}
