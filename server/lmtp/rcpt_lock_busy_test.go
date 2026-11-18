//go:build integration

package lmtp_test

import (
	"errors"
	"testing"

	"github.com/emersion/go-smtp"
	"github.com/migadu/sora/integration_tests/common"
	lmtpserver "github.com/migadu/sora/server/lmtp"
)

// A RCPT that cannot take the session lock in time is answered 451 4.4.5, a temporary
// failure, like MAIL and DATA (TestLockBusyReply): not 421, which announces that the
// server closes the connection, when it does not (#2047).
func TestRcptLockBusyReply(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	var reply *smtp.SMTPError
	if err := lmtpserver.RcptWhileLockedForTest(rdb, account.Email); !errors.As(err, &reply) {
		t.Fatalf("RCPT = %v, want an SMTP reply", err)
	}
	if reply.Code != 451 || reply.EnhancedCode != (smtp.EnhancedCode{4, 4, 5}) || reply.Message != "Server busy, try again later" {
		t.Fatalf("RCPT = %d %v %q, want 451 4.4.5 Server busy, try again later", reply.Code, reply.EnhancedCode, reply.Message)
	}
}
