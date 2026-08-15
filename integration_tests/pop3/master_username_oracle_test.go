//go:build integration

package pop3_test

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
)

// TestPOP3_MasterUsername_WrongPasswordIsNotAUsernameOracle closes the last distinct reply
// in the master-auth family for POP3: a WRONG master password on a correct master username
// suffix. It must be byte-identical to an ordinary bad-credential reply, or the reply
// enumerates the configured master username (reachable with no secret) — the precondition
// for every other master-form attack. See the IMAP twin for the full rationale.
func TestPOP3_MasterUsername_WrongPasswordIsNotAUsernameOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	const masterUser = "pop3_master_admin"
	const masterPass = "pop3_master_secret"

	address := startPOP3WithMasterUsername(t, rdb, server.AuthRateLimiterConfig{Enabled: false}, masterUser, masterPass)

	notMaster := pop3UserPass(t, address, account.Email+"@not-the-master", "whatever")
	if !strings.HasPrefix(notMaster, "-ERR") {
		t.Fatalf("expected -ERR for a non-master suffix, got %q", notMaster)
	}

	wrongMasterPw := pop3UserPass(t, address, account.Email+"@"+masterUser, "wrong-master-password")
	if !strings.HasPrefix(wrongMasterPw, "-ERR") {
		t.Fatalf("expected -ERR for a wrong master password, got %q", wrongMasterPw)
	}

	if wrongMasterPw != notMaster {
		t.Errorf("a wrong master password on the correct master username is answered differently from an "+
			"ordinary bad credential, so it confirms the configured master username to anyone who can reach "+
			"the port:\n\tnon-master suffix:        %q\n\tcorrect master, wrong pw: %q", notMaster, wrongMasterPw)
	}
}
