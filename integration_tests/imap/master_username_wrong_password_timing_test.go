//go:build integration

package imap_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	serverImap "github.com/migadu/sora/server/imap"
	"github.com/migadu/sora/storage"
	"github.com/migadu/sora/testutils"
)

// TestIMAP_MasterUsernameWrongPasswordIsNotAMasterUsernameOracle (#801): a wrong password
// in the master username form "user@domain.com@MASTERUSER" is refused like a wrong
// password under any other suffix: the same reply after the same password verification,
// the regular check of the base address. The master password used to be compared and
// refused without one, so the response time confirmed a guessed master username. The
// account's own password logs in through the master form as through any other suffix
// (#949). Both verbs, both cache modes; the verifications are counted, not timed (#782).
func TestIMAP_MasterUsernameWrongPasswordIsNotAMasterUsernameOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	const masterUser, masterPass = "masteruser", "master-secret"

	verbs := []struct {
		name  string
		probe func(t *testing.T, address, username, password string) string
	}{
		{"LOGIN", imapLoginReply},
		{"AUTHENTICATE_PLAIN", func(t *testing.T, address, username, password string) string {
			t.Helper()
			return imapAuthPlain(t, address, "", username, password)
		}},
	}

	for _, verb := range verbs {
		for _, cacheEnabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/cache=%v", verb.name, cacheEnabled), func(t *testing.T) {
				// A server per subtest: a cached login would make the next one cheaper.
				address := common.GetRandomAddress(t)
				srv, err := serverImap.New(context.Background(), "test-master-username-timing", "localhost", address,
					&storage.S3Storage{}, rdb, nil, nil,
					serverImap.IMAPServerOptions{
						InsecureAuth:   true,
						MasterUsername: []byte(masterUser),
						MasterPassword: []byte(masterPass),
						LookupCache:    &config.LookupCacheConfig{Enabled: cacheEnabled},
					})
				if err != nil {
					t.Fatalf("Failed to create IMAP server: %v", err)
				}
				go func() {
					if err := srv.Serve(address); err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
						t.Logf("IMAP server stopped: %v", err)
					}
				}()
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

				// The account's own password logs in under the master suffix as under any
				// other (#949). Not counted: whichever comes first is cached for the other.
				ownMaster, _ := counted(account.Email+"@"+masterUser, account.Password)
				ownOther, _ := counted(account.Email+"@other", account.Password)
				if ownMaster != ownOther || !strings.Contains(ownOther, " OK ") {
					t.Errorf("the account's own password:\n  master suffix: %q\n  other suffix:  %q\nwant the same login: a refusal under the master suffix alone confirms the master username", ownMaster, ownOther)
				}
			})
		}
	}
}
