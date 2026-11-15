//go:build integration

package pop3_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
)

// TestPOP3LoginResultLoggedOnceThroughSession: the result of a regular login is logged
// once, by the session, so the line can be tied to the client and to the session's
// other lines (protocol, remote, session, and on success user/account_id), and its
// cached/method say how the password was checked. The second login with the same
// password is answered by the lookup cache, the wrong passwords by the database. The
// last login has the right password but asks to act as another user: it is refused
// for authorization, and that is its result.
func TestPOP3LoginResultLoggedOnceThroughSession(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)
	other := common.CreateTestAccount(t, rdb)
	address := startPOP3WithMasterSASL(t, rdb, server.AuthRateLimiterConfig{}, "", "")
	logs := common.CaptureLogs(t)

	for _, cmd := range pop3LoginCommands {
		if reply := cmd.login(t, address, account.Email, account.Password); !strings.HasPrefix(reply, "+OK") {
			t.Fatalf("%s with the right password: %q, want +OK", cmd.name, reply)
		}
	}
	for _, cmd := range pop3LoginCommands {
		if reply := cmd.login(t, address, account.Email, "wrong-password"); !strings.HasPrefix(reply, "-ERR [AUTH]") {
			t.Fatalf("%s with a wrong password: %q, want -ERR [AUTH] ...", cmd.name, reply)
		}
	}
	if reply := pop3AuthPlain(t, address, other.Email, account.Email, account.Password); reply != "-ERR [AUTH] Proxy authentication requires master credentials" {
		t.Fatalf("AUTH PLAIN acting as another user: %q, want the authorization refusal", reply)
	}

	success := []string{"protocol=POP3-", "user=" + account.Email, `msg="authentication successful"`}
	failed := []string{"protocol=POP3-", "address=" + account.Email, `msg="authentication failed"`, "reason=invalid_password", "cached=false", "method=main_db"}
	common.RequireLoginResults(t, logs, account.Email,
		slices.Concat(success, []string{"cached=false", "method=main_db"}),
		slices.Concat(success, []string{"cached=true", "method=cache"}),
		failed,
		failed,
		[]string{"protocol=POP3-", "address=" + account.Email, `msg="authorization failed"`, "authzid=" + other.Email, "method=main_db"},
	)
}
