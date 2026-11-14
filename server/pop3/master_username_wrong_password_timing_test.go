//go:build integration

package pop3_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/storage"
	"github.com/migadu/sora/testutils"
)

// TestPOP3_MasterUsernameWrongPasswordIsNotAMasterUsernameOracle (#801): a wrong password
// in the master username form "user@domain.com@MASTERUSER" is refused like a wrong
// password under any other suffix: the same reply after the same password verification,
// the regular check of the base address. The master password used to be compared and
// refused without one, so the response time confirmed a guessed master username. The
// account's own password does not log in through the master form (any other suffix
// would), but it is refused after the same verification. USER/PASS and AUTH PLAIN, both
// cache modes. The session is driven directly: over the wire every failed command is
// held back by the POP3 error delay, which would hide the difference. The verifications
// are counted, not timed (#782).
func TestPOP3_MasterUsernameWrongPasswordIsNotAMasterUsernameOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	const masterUser, masterPass = "masteruser", "master-secret"

	verbs := []struct {
		name  string
		login func(s *pop3.POP3Session, username, password string) error
	}{
		{"USER_PASS", func(s *pop3.POP3Session, username, password string) error {
			return s.Login(context.Background(), username, password)
		}},
		{"AUTH_PLAIN", func(s *pop3.POP3Session, username, password string) error {
			return s.AuthenticatePlain(context.Background(), "", username, password)
		}},
	}

	for _, verb := range verbs {
		for _, cacheEnabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cache=%v", verb.name, cacheEnabled), func(t *testing.T) {
				// A server per subtest: a cached login would make the next one cheaper.
				srv, err := pop3.New(context.Background(), "test-master-username-timing", "localhost", common.GetRandomAddress(t),
					&storage.S3Storage{}, rdb, nil, nil,
					pop3.POP3ServerOptions{
						InsecureAuth:   true,
						Config:         &config.Config{},
						MasterUsername: masterUser,
						MasterPassword: masterPass,
						LookupCache:    &config.LookupCacheConfig{Enabled: cacheEnabled},
					})
				if err != nil {
					t.Fatalf("Failed to create POP3 server: %v", err)
				}
				t.Cleanup(srv.Close)

				counted := func(username, password string) (string, int) {
					c1, c2 := net.Pipe()
					defer c1.Close()
					defer c2.Close()
					session := pop3.NewSessionForTest(srv, c1)
					before := testutils.PasswordVerifications()
					err := verb.login(session, username, password)
					return fmt.Sprintf("%#v", err), testutils.PasswordVerifications() - before
				}

				unknown := fmt.Sprintf("nobody-%d@example.com", time.Now().UnixNano())
				for _, base := range []string{unknown, account.Email} {
					otherReply, otherVerified := counted(base+"@other", "wrong-password")
					masterReply, masterVerified := counted(base+"@"+masterUser, "wrong-password")
					if masterReply != otherReply {
						t.Fatalf("%s: wrong password answered differently by suffix:\n  other suffix:  %s\n  master suffix: %s", base, otherReply, masterReply)
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
					t.Fatalf("the account's own password under the master suffix: %s, want the wrong-password reply %s", ownReply, wrongReply)
				}
				if ownVerified != 1 {
					t.Errorf("the account's own password under the master suffix refused after %d password verifications, want 1", ownVerified)
				}
			})
		}
	}
}
