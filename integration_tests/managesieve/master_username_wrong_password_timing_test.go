//go:build integration

package managesieve

import (
	"context"
	"fmt"
	"strings"
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
// username. The account's own password logs in through the master form as through any
// other suffix (#949). Both verbs, both cache modes; the verifications are counted, not
// timed (#782).
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

				// The account's own password logs in under the master suffix as under any
				// other (#949). Not counted: whichever comes first is cached for the other.
				ownMaster, _ := counted(account.Email+"@"+masterUser, account.Password)
				ownOther, _ := counted(account.Email+"@other", account.Password)
				if ownMaster != ownOther || !strings.HasPrefix(ownOther, "OK") {
					t.Errorf("the account's own password:\n  master suffix: %q\n  other suffix:  %q\nwant the same login: a refusal under the master suffix alone confirms the master username", ownMaster, ownOther)
				}
			})
		}
	}
}

// TestManageSieve_MasterUsernameRefusalsCostAWrongMasterPassword (#801): every refusal of
// the CORRECT master password in the master username form costs what a wrong master
// password costs, one password verification, as well as being answered like one. A wrong
// master password is refused after the regular check of the base address; a refusal that
// skips it (the source is outside master_sasl_allowed_networks, the target does not parse
// or has no account) is answered one verification sooner and confirms the guessed
// password, to a peer the gate keeps out, without completing an authentication. The
// verifications are counted, not timed (#782).
func TestManageSieve_MasterUsernameRefusalsCostAWrongMasterPassword(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)
	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	const masterUser, masterPass = "masteruser", "master-secret"

	start := func(allowedNetworks []string) string {
		address := common.GetRandomAddress(t)
		srv, err := managesieve.New(context.Background(), "test-master-username-refusals", "localhost", address, rdb,
			managesieve.ManageSieveServerOptions{
				Config:                    &config.Config{},
				InsecureAuth:              true,
				MasterUsername:            masterUser,
				MasterPassword:            masterPass,
				MasterSASLAllowedNetworks: allowedNetworks,
				LookupCache:               &config.LookupCacheConfig{Enabled: false},
			})
		if err != nil {
			t.Fatalf("Failed to create ManageSieve server: %v", err)
		}
		errChan := make(chan error, 1)
		go func() { srv.Start(errChan) }()
		time.Sleep(100 * time.Millisecond)
		t.Cleanup(func() { srv.Close() })
		return address
	}
	open := start(nil)
	gated := start([]string{"10.0.0.0/8"}) // loopback is outside it

	counted := func(probe func() string) (string, int) {
		before := testutils.PasswordVerifications()
		reply := probe()
		return reply, testutils.PasswordVerifications() - before
	}
	login := func(address, username, password string) func() string {
		return func() string { return msLogin(t, address, username, password) }
	}
	authPlain := func(address, authzID, authnID, password string) func() string {
		return func() string { return msAuthPlain(t, address, authzID, authnID, password) }
	}

	masterForm := account.Email + "@" + masterUser
	unknownForm := fmt.Sprintf("nobody-%d@example.com@%s", time.Now().UnixNano(), masterUser)

	type refusal struct {
		name  string
		probe func() string
	}
	for _, verb := range []struct {
		name  string
		wrong func() string
		cases []refusal
	}{
		{"AUTHENTICATE_PLAIN", authPlain(open, "", masterForm, "wrong-password"), []refusal{
			{"source_not_allowed", authPlain(gated, "", masterForm, masterPass)},
			{"malformed_target", authPlain(open, "not-an-address", masterForm, masterPass)},
			{"unknown_target", authPlain(open, "", unknownForm, masterPass)},
		}},
		{"LOGIN", login(open, masterForm, "wrong-password"), []refusal{
			{"source_not_allowed", login(gated, masterForm, masterPass)},
			{"unknown_target", login(open, unknownForm, masterPass)},
		}},
	} {
		t.Run(verb.name, func(t *testing.T) {
			wrongReply, wrongVerified := counted(verb.wrong)
			if !strings.HasPrefix(wrongReply, "NO") || wrongVerified != 1 {
				t.Fatalf("control: wrong master password: %q after %d password verifications, want a refusal after 1", wrongReply, wrongVerified)
			}
			for _, c := range verb.cases {
				reply, verified := counted(c.probe)
				if reply != wrongReply {
					t.Errorf("%s: %q, a wrong master password: %q", c.name, reply, wrongReply)
				}
				if verified != wrongVerified {
					t.Errorf("%s: refused after %d password verifications, a wrong master password after %d: the response time confirms the master password", c.name, verified, wrongVerified)
				}
			}
		})
	}
}
