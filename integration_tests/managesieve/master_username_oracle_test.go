//go:build integration

package managesieve

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
)

// TestManageSieve_MasterUsername_WrongPasswordIsNotAUsernameOracle closes the last distinct
// reply in the master-auth family for ManageSieve: a WRONG master password on a correct
// master username suffix. Both verbs that reach the master form (AUTHENTICATE PLAIN and
// LOGIN) are probed, since each is a different function with its own reply. The reply must
// be byte-identical to an ordinary bad-credential reply, or it enumerates the configured
// master username with no secret. See the IMAP twin for the full rationale.
func TestManageSieve_MasterUsername_WrongPasswordIsNotAUsernameOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	const masterUser = "ms_master_admin"
	const masterPass = "ms_master_secret"

	for _, verb := range masterUsernameVerbs {
		t.Run(verb.name, func(t *testing.T) {
			address := startManageSieveWithMasterUsername(t, rdb, server.AuthRateLimiterConfig{Enabled: false}, masterUser, masterPass)

			notMaster := verb.probe(t, address, account.Email+"@not-the-master", "whatever")
			if !strings.HasPrefix(notMaster, "NO") {
				t.Fatalf("expected NO for a non-master suffix, got %q", notMaster)
			}

			wrongMasterPw := verb.probe(t, address, account.Email+"@"+masterUser, "wrong-master-password")
			if !strings.HasPrefix(wrongMasterPw, "NO") {
				t.Fatalf("expected NO for a wrong master password, got %q", wrongMasterPw)
			}

			if wrongMasterPw != notMaster {
				t.Errorf("a wrong master password on the correct master username is answered differently from "+
					"an ordinary bad credential, so it confirms the configured master username to anyone who can "+
					"reach the port:\n\tnon-master suffix:        %q\n\tcorrect master, wrong pw: %q", notMaster, wrongMasterPw)
			}
		})
	}
}
