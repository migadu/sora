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
// account's own password logs in through the master form as through any other suffix
// (#949). USER/PASS and AUTH PLAIN, both cache modes. The session is driven directly: over the wire every failed command is
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

				// The account's own password logs in under the master suffix as under any
				// other (#949). Not counted: whichever comes first is cached for the other.
				ownMaster, _ := counted(account.Email+"@"+masterUser, account.Password)
				ownOther, _ := counted(account.Email+"@other", account.Password)
				if ownMaster != ownOther || ownOther != "<nil>" {
					t.Errorf("the account's own password:\n  master suffix: %s\n  other suffix:  %s\nwant the same login: a refusal under the master suffix alone confirms the master username", ownMaster, ownOther)
				}
			})
		}
	}
}

// TestPOP3_MasterUsernameRefusalsCostAWrongMasterPassword (#801): every refusal of the
// CORRECT master password in the master username form costs what a wrong master password
// costs, one password verification, as well as being answered like one. A wrong master
// password is refused after the regular check of the base address; a refusal that skips
// it (the source is outside master_sasl_allowed_networks, the target does not parse or
// has no account) is answered one verification sooner and confirms the guessed password,
// to a peer the gate keeps out, without completing an authentication. The session is
// driven directly (see above); its pipe peer is outside any allowed network.
func TestPOP3_MasterUsernameRefusalsCostAWrongMasterPassword(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	const masterUser, masterPass = "masteruser", "master-secret"

	start := func(allowedNetworks []string) *pop3.POP3Server {
		srv, err := pop3.New(context.Background(), "test-master-username-refusals", "localhost", common.GetRandomAddress(t),
			&storage.S3Storage{}, rdb, nil, nil,
			pop3.POP3ServerOptions{
				InsecureAuth:              true,
				Config:                    &config.Config{},
				MasterUsername:            masterUser,
				MasterPassword:            masterPass,
				MasterSASLAllowedNetworks: allowedNetworks,
				LookupCache:               &config.LookupCacheConfig{Enabled: false},
			})
		if err != nil {
			t.Fatalf("Failed to create POP3 server: %v", err)
		}
		t.Cleanup(srv.Close)
		return srv
	}
	open, gated := start(nil), start([]string{"10.0.0.0/8"})

	counted := func(srv *pop3.POP3Server, login func(s *pop3.POP3Session) error) (string, int) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		session := pop3.NewSessionForTest(srv, c1)
		before := testutils.PasswordVerifications()
		err := login(session)
		return fmt.Sprintf("%#v", err), testutils.PasswordVerifications() - before
	}
	userPass := func(username, password string) func(s *pop3.POP3Session) error {
		return func(s *pop3.POP3Session) error { return s.Login(context.Background(), username, password) }
	}
	authPlain := func(identity, username, password string) func(s *pop3.POP3Session) error {
		return func(s *pop3.POP3Session) error {
			return s.AuthenticatePlain(context.Background(), identity, username, password)
		}
	}

	masterForm := account.Email + "@" + masterUser
	unknownForm := fmt.Sprintf("nobody-%d@example.com@%s", time.Now().UnixNano(), masterUser)

	type refusal struct {
		name  string
		srv   *pop3.POP3Server
		login func(s *pop3.POP3Session) error
	}
	for _, verb := range []struct {
		name  string
		wrong func(s *pop3.POP3Session) error
		cases []refusal
	}{
		{"USER_PASS", userPass(masterForm, "wrong-password"), []refusal{
			{"source_not_allowed", gated, userPass(masterForm, masterPass)},
			{"unknown_target", open, userPass(unknownForm, masterPass)},
		}},
		{"AUTH_PLAIN", authPlain("", masterForm, "wrong-password"), []refusal{
			{"source_not_allowed", gated, authPlain("", masterForm, masterPass)},
			{"malformed_target", open, authPlain("not-an-address", masterForm, masterPass)},
			{"unknown_target", open, authPlain("", unknownForm, masterPass)},
		}},
	} {
		t.Run(verb.name, func(t *testing.T) {
			wrongReply, wrongVerified := counted(open, verb.wrong)
			if wrongVerified != 1 {
				t.Fatalf("control: wrong master password refused after %d password verifications, want 1", wrongVerified)
			}
			for _, c := range verb.cases {
				reply, verified := counted(c.srv, c.login)
				if reply != wrongReply {
					t.Errorf("%s: %s, a wrong master password: %s", c.name, reply, wrongReply)
				}
				if verified != wrongVerified {
					t.Errorf("%s: refused after %d password verifications, a wrong master password after %d: the response time confirms the master password", c.name, verified, wrongVerified)
				}
			}
		})
	}
}
