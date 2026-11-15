//go:build integration

package managesieve

import (
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
)

// TestManageSieveLoginResultLoggedOnceThroughSession: the result of a regular login is
// logged once, by the session, so the line can be tied to the client and to the
// session's other lines (protocol, remote, session, and on success user/account_id),
// and its cached/method say how the password was checked. The second login with the
// same password is answered by the lookup cache, the wrong passwords by the database.
// AUTHENTICATE and LOGIN authenticate in separate functions, so both are probed.
func TestManageSieveLoginResultLoggedOnceThroughSession(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	address := startManageSieveWithMasterSASL(t, rdb, server.AuthRateLimiterConfig{}, "", "")
	logs := common.CaptureLogs(t)

	for _, verb := range masterUsernameVerbs {
		if reply := verb.probe(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "OK") {
			t.Fatalf("%s with the right password: %q, want OK", verb.name, reply)
		}
	}
	for _, verb := range masterUsernameVerbs {
		if reply := verb.probe(t, address, account.Email, "wrong-password"); !strings.HasPrefix(reply, "NO") {
			t.Fatalf("%s with a wrong password: %q, want NO", verb.name, reply)
		}
	}

	success := []string{"protocol=ManageSieve-", "user=" + account.Email, `msg="authentication successful"`}
	failed := []string{"protocol=ManageSieve-", "address=" + account.Email, `msg="authentication failed"`, "reason=invalid_password", "cached=false", "method=main_db"}
	common.RequireLoginResults(t, logs, account.Email,
		slices.Concat(success, []string{"cached=false", "method=main_db"}),
		slices.Concat(success, []string{"cached=true", "method=cache"}),
		failed,
		failed,
	)
}
