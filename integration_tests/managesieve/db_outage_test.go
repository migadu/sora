//go:build integration

package managesieve

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
)

// TestManageSieveLoginDuringDatabaseOutage: a login the database cannot answer is a
// temporary failure, NO (TRYLATER) (RFC 5804 section 1.3), not a failed
// authentication, and it is not counted by the auth rate limiter, so the user logs in
// once the database is back. AUTHENTICATE and LOGIN authenticate in separate
// functions, so both are probed.
func TestManageSieveLoginDuringDatabaseOutage(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb, outage := common.SetupTestDatabaseWithOutage(t)
	account := common.CreateTestAccount(t, rdb)
	address := startManageSieveWithMasterSASL(t, rdb, common.DBOutageAuthRateLimit(), "", "")

	outage.Begin()
	for _, verb := range masterUsernameVerbs {
		for i := 1; i <= 2; i++ {
			if reply := verb.probe(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "NO (TRYLATER)") {
				t.Errorf("%s %d during a database outage: %q, want NO (TRYLATER) ...", verb.name, i, reply)
			}
		}
	}
	outage.End()

	for _, verb := range masterUsernameVerbs {
		if reply := verb.probe(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "OK") {
			t.Errorf("%s after the outage: %q, want OK (the outage was counted as failed logins)", verb.name, reply)
		}
	}
}
