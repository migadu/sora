//go:build integration

package managesieve

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/config"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieve"
)

// startManageSieveWithMasterSASL starts a ManageSieve backend with the given
// master SASL credentials against an ALREADY created account, so a test can make
// the master SASL username collide with a real account address.
func startManageSieveWithMasterSASL(t *testing.T, rdb *resilient.ResilientDatabase, rateLimit server.AuthRateLimiterConfig, saslUser, saslPass string) string {
	t.Helper()

	address := common.GetRandomAddress(t)
	srv, err := managesieve.New(
		context.Background(),
		"test-master-sasl-no-authzid",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			Config:             &config.Config{},
			InsecureAuth:       true, // Allow authentication over non-TLS connection for testing
			AuthRateLimit:      rateLimit,
			MasterSASLUsername: saslUser,
			MasterSASLPassword: saslPass,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create ManageSieve server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() { srv.Start(errChan) }()
	time.Sleep(100 * time.Millisecond)
	t.Cleanup(func() { srv.Close() })

	return address
}

// msAuthPlain performs one AUTHENTICATE PLAIN exchange on a fresh connection and
// returns the verbatim response line.
func msAuthPlain(t *testing.T, address, authzID, authnID, password string) string {
	t.Helper()

	client, err := NewManageSieveClient(address)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	encoded := base64.StdEncoding.EncodeToString([]byte(authzID + "\x00" + authnID + "\x00" + password))
	if err := client.SendCommand(fmt.Sprintf("AUTHENTICATE \"PLAIN\" \"%s\"", encoded)); err != nil {
		t.Fatalf("AUTHENTICATE: %v", err)
	}
	resp, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("AUTHENTICATE read: %v", err)
	}
	return resp
}

// TestManageSieve_MasterSASL_NoAuthzIDIsNotAPasswordOracle proves that with an
// EMPTY authorization identity the server's answer does not depend on whether the
// master SASL password was correct.
//
// The master credential impersonates any tenant. A reply that is only reachable
// with the correct master password ("Master SASL login requires an authorization
// identity.") let anyone who can reach the port confirm a guessed master password
// without ever completing an authentication.
//
// The two probe sequences run against two servers with IDENTICAL configuration so
// the comparison also covers the rate-limiter state: if only one of the two cases
// were recorded as a failure, the sequences would diverge at the block threshold
// even when every individual message matched.
func TestManageSieve_MasterSASL_NoAuthzIDIsNotAPasswordOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)

	const saslPass = "master_sasl_secret_pw"
	// Tier 1 only; Tier 2 and progressive delays disabled so the comparison is on
	// the responses and on blocking, never on timing.
	rateLimit := server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  2 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         0,   // Tier 2 disabled
		DelayStartThreshold:      100, // delays disabled
		CleanupInterval:          1 * time.Minute,
	}

	shapes := []struct {
		name     string
		saslUser string
	}{
		// Documented master_sasl_username shape: not an email address.
		{"non_address_master_username", fmt.Sprintf("proxyuser-%d", time.Now().UnixNano())},
		// Address-shaped master username (no such account exists).
		{"address_shaped_master_username", fmt.Sprintf("proxy-%d@example.com", time.Now().UnixNano())},
	}

	for _, shape := range shapes {
		t.Run(shape.name, func(t *testing.T) {
			// One server per password, so each probe sequence gets its own
			// rate-limiter state.
			correctAddr := startManageSieveWithMasterSASL(t, rdb, rateLimit, shape.saslUser, saslPass)
			wrongAddr := startManageSieveWithMasterSASL(t, rdb, rateLimit, shape.saslUser, saslPass)

			// Enough attempts to cross the Tier-1 threshold (3) on both sides.
			const attempts = 5

			for i := 0; i < attempts; i++ {
				withMaster := msAuthPlain(t, correctAddr, "", shape.saslUser, saslPass)
				withWrong := msAuthPlain(t, wrongAddr, "", shape.saslUser, fmt.Sprintf("wrong-master-pw-%d", i))

				if strings.HasPrefix(withMaster, "OK") {
					t.Fatalf("attempt %d: master SASL password with an empty authorization identity must not authenticate, got %q", i+1, withMaster)
				}
				if withMaster != withWrong {
					t.Fatalf("attempt %d: response is a master-password oracle\n  correct master password: %q\n  wrong master password:   %q", i+1, withMaster, withWrong)
				}
			}
		})
	}
}

// TestManageSieve_MasterSASL_NoAuthzIDCorrectPasswordIsRecorded proves that
// presenting the master SASL password without an authorization identity is
// recorded as an authentication failure and therefore consumes the master
// credential's rate-limit budget, exactly like a wrong password does.
func TestManageSieve_MasterSASL_NoAuthzIDCorrectPasswordIsRecorded(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// Documented master_sasl_username shape: not an email address, so the regular
	// path cannot record anything for it on its own.
	saslUser := fmt.Sprintf("proxyuser-%d", time.Now().UnixNano())
	const saslPass = "master_sasl_secret_pw"

	rateLimit := server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  2 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         0,   // Tier 2 disabled
		DelayStartThreshold:      100, // delays disabled
		CleanupInterval:          1 * time.Minute,
	}

	// Control: on an untouched server the master credential WITH an authorization
	// identity authenticates, so the assertion below cannot pass merely because
	// master SASL is broken.
	control := startManageSieveWithMasterSASL(t, rdb, rateLimit, saslUser, saslPass)
	if resp := msAuthPlain(t, control, account.Email, saslUser, saslPass); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("control: master SASL impersonation must work, got %q", resp)
	}

	probed := startManageSieveWithMasterSASL(t, rdb, rateLimit, saslUser, saslPass)

	// Burn the Tier-1 budget with the CORRECT master password and no authzid.
	for i := 0; i < 3; i++ {
		if resp := msAuthPlain(t, probed, "", saslUser, saslPass); strings.HasPrefix(resp, "OK") {
			t.Fatalf("attempt %d: master password without an authorization identity must not authenticate, got %q", i+1, resp)
		}
	}

	// The master credential must now be blocked: only possible if the probes above
	// were recorded as authentication failures under the master credential's key.
	if resp := msAuthPlain(t, probed, account.Email, saslUser, saslPass); strings.HasPrefix(resp, "OK") {
		t.Fatalf("master SASL still usable after 3 no-authzid probes with the correct master password: the probes are not recorded/rate limited, got %q", resp)
	} else {
		t.Logf("✓ master SASL blocked after 3 no-authzid probes: %s", resp)
	}
}

// TestManageSieve_MasterSASLUsernameIsARealAccount covers the deployment where
// master_sasl_username is also a real account's address (e.g. an operator's own
// mailbox). That account must keep working with its OWN password, and the proxy's
// impersonation of it must keep working too.
func TestManageSieve_MasterSASLUsernameIsARealAccount(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	// The master SASL username IS this account's address.
	saslUser := account.Email
	const saslPass = "master_sasl_secret_pw"

	address := startManageSieveWithMasterSASL(t, rdb, server.AuthRateLimiterConfig{Enabled: false}, saslUser, saslPass)

	// SASL PLAIN with an empty authorization identity and the account's own password.
	if resp := msAuthPlain(t, address, "", account.Email, account.Password); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("account whose address is master_sasl_username cannot log in with its own password over AUTHENTICATE PLAIN: %q", resp)
	}

	// SASL PLAIN with authzid == authcid and the account's OWN password. RFC 4616 says an
	// authorization identity equal to the authentication identity means "no impersonation",
	// and several SASL client libraries fill the field in unconditionally, so this is an
	// ordinary login that happens to name itself. Answering it from the master-SASL branch -
	// where the password does not match the master password - locks this account out of its
	// own mailbox permanently.
	if resp := msAuthPlain(t, address, account.Email, account.Email, account.Password); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("account whose address is master_sasl_username cannot log in with its own password when "+
			"the client sends authzid == authcid (RFC 4616 'no impersonation'): %q", resp)
	}

	// The proxy flow must survive: managesieveproxy sends authzid=<user>,
	// authcid=<master SASL username>, which for this account are the same string.
	if resp := msAuthPlain(t, address, account.Email, saslUser, saslPass); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("master SASL impersonation of the account sharing the master username must still work: %q", resp)
	}

	// The master password alone still grants nothing without an authorization identity.
	if resp := msAuthPlain(t, address, "", saslUser, saslPass); strings.HasPrefix(resp, "OK") {
		t.Fatalf("master password with no authorization identity must not authenticate, got %q", resp)
	}
}
