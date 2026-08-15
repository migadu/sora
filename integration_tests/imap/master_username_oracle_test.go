//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
)

// TestIMAP_MasterUsername_WrongPasswordIsNotAUsernameOracle closes the last distinct reply
// in the master-auth family: the one for a WRONG master password on a correct master
// username suffix.
//
// The master forms (user@domain@MASTERUSER) are reachable with only the master USERNAME -
// no secret. If a wrong master password there returns a reply distinct from an ordinary
// bad-credential reply, an attacker who cannot guess the password can still enumerate the
// configured master username by watching which suffix flips the reply. That username is the
// precondition for every other master-form attack, so the reply for a wrong master password
// must be byte-identical to the reply for a suffix that is NOT the master username.
func TestIMAP_MasterUsername_WrongPasswordIsNotAUsernameOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	const masterUser = "imap_master_admin"
	const masterPass = "imap_master_secret"

	// Rate limiting disabled: this test is about the reply text, and a limiter would start
	// refusing attempts for an unrelated reason.
	address := startIMAPWithMasterUsername(t, rdb, server.AuthRateLimiterConfig{Enabled: false}, masterUser, masterPass)

	// A suffix that is NOT the master username: the ordinary bad-credential reply.
	notMaster := imapRawCommand(t, address, fmt.Sprintf("LOGIN %q %q", account.Email+"@not-the-master", "whatever"))
	if !strings.HasPrefix(notMaster, "A001 NO") {
		t.Fatalf("expected a NO for a non-master suffix, got %q", notMaster)
	}

	// The CORRECT master username suffix with a WRONG master password. Before the fix this
	// answered "Invalid master credentials", confirming the username.
	wrongMasterPw := imapRawCommand(t, address, fmt.Sprintf("LOGIN %q %q", account.Email+"@"+masterUser, "wrong-master-password"))
	if !strings.HasPrefix(wrongMasterPw, "A001 NO") {
		t.Fatalf("expected a NO for a wrong master password, got %q", wrongMasterPw)
	}

	if wrongMasterPw != notMaster {
		t.Errorf("a wrong master password on the correct master username is answered differently from an "+
			"ordinary bad credential, so it confirms the configured master username to anyone who can reach "+
			"the port:\n\tnon-master suffix:    %q\n\tcorrect master, wrong pw: %q", notMaster, wrongMasterPw)
	}
}
