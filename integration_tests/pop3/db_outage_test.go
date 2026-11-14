//go:build integration

package pop3_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestPOP3LoginDuringDatabaseOutage: a login the database cannot answer is a temporary
// failure, -ERR [SYS/TEMP] (RFC 3206 section 4), not [AUTH], and it is not counted by
// the auth rate limiter, so the user logs in once the database is back.
func TestPOP3LoginDuringDatabaseOutage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	account := common.CreateTestAccount(t, rdb)
	address := startPOP3WithMasterSASL(t, rdb, common.DBOutageAuthRateLimit(), "", "")

	outage.Begin()
	for i := 1; i <= 3; i++ {
		if reply := pop3UserPass(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "-ERR [SYS/TEMP]") {
			t.Errorf("PASS %d during a database outage: %q, want -ERR [SYS/TEMP] ...", i, reply)
		}
	}
	outage.End()

	if reply := pop3UserPass(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "+OK") {
		t.Errorf("PASS after the outage: %q, want +OK (the outage was counted as failed logins)", reply)
	}
}
