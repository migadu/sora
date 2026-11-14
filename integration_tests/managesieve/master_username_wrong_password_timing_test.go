//go:build integration

package managesieve

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/managesieve"
	"github.com/migadu/sora/testutils"
)

// TestManageSieve_MasterUsernameWrongPasswordIsNotAMasterUsernameOracle (#801): a wrong
// password in the master username form "user@domain.com@MASTERUSER" is refused like a
// wrong password under any other suffix: the same reply after the same password
// verification, the regular check of the base address. The master password used to be
// compared and refused without one, so the response time confirmed a guessed master
// username. The account's own password does not log in through the master form (any
// other suffix would), but it is refused after the same verification. Both verbs, both
// cache modes; the verifications are counted, not timed (#782).
func TestManageSieve_MasterUsernameWrongPasswordIsNotAMasterUsernameOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	const masterUser, masterPass = "masteruser", "master-secret"

	for _, verb := range masterUsernameVerbs {
		for _, cacheEnabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cache=%v", verb.name, cacheEnabled), func(t *testing.T) {
				// A server per subtest: a cached login would make the next one cheaper.
				address := common.GetRandomAddress(t)
				srv, err := managesieve.New(context.Background(), "test-master-username-timing", "localhost", address, rdb,
					managesieve.ManageSieveServerOptions{
						Config:         &config.Config{},
						InsecureAuth:   true,
						MasterUsername: masterUser,
						MasterPassword: masterPass,
						LookupCache:    &config.LookupCacheConfig{Enabled: cacheEnabled},
					})
				if err != nil {
					t.Fatalf("Failed to create ManageSieve server: %v", err)
				}
				errChan := make(chan error, 1)
				go func() { srv.Start(errChan) }()
				time.Sleep(100 * time.Millisecond)
				t.Cleanup(func() { srv.Close() })

				counted := func(username, password string) (string, int) {
					before := testutils.PasswordVerifications()
					reply := verb.probe(t, address, username, password)
					return reply, testutils.PasswordVerifications() - before
				}

				unknown := fmt.Sprintf("nobody-%d@example.com", time.Now().UnixNano())
				for _, base := range []string{unknown, account.Email} {
					otherReply, otherVerified := counted(base+"@other", "wrong-password")
					masterReply, masterVerified := counted(base+"@"+masterUser, "wrong-password")
					if masterReply != otherReply {
						t.Fatalf("%s: wrong password answered differently by suffix:\n  other suffix:  %q\n  master suffix: %q", base, otherReply, masterReply)
					}
					if otherVerified != 1 {
						t.Fatalf("%s: wrong password under another suffix answered after %d password verifications, want 1", base, otherVerified)
					}
					if masterVerified != otherVerified {
						t.Errorf("%s: wrong password under the master suffix answered after %d password verifications, under another suffix after %d: the response time confirms the master username", base, masterVerified, otherVerified)
					}
				}

				ownReply, ownVerified := counted(account.Email+"@"+masterUser, account.Password)
				wrongReply, _ := counted(account.Email+"@other", "wrong-password")
				if ownReply != wrongReply {
					t.Fatalf("the account's own password under the master suffix: %q, want the wrong-password reply %q", ownReply, wrongReply)
				}
				if ownVerified != 1 {
					t.Errorf("the account's own password under the master suffix refused after %d password verifications, want 1", ownVerified)
				}
			})
		}
	}
}
