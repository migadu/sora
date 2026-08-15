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
	"github.com/migadu/sora/pkg/resilient"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/managesieve"
)

// startManageSieveWithMasterUsername starts a ManageSieve backend configured with
// the "user@domain.com@MASTERUSER" master form (master_username/master_password).
// That form names the impersonation target INSIDE the authentication identity, so
// its canonical rate-limit key (server.AuthRateLimitKey) is the TARGET's address —
// which is exactly the key a master-credential attempt must not use.
func startManageSieveWithMasterUsername(t *testing.T, rdb *resilient.ResilientDatabase, rateLimit server.AuthRateLimiterConfig, masterUser, masterPass string) string {
	t.Helper()

	address := common.GetRandomAddress(t)
	srv, err := managesieve.New(
		context.Background(),
		"test-master-username-ratelimit-key",
		"localhost",
		address,
		rdb,
		managesieve.ManageSieveServerOptions{
			Config:         &config.Config{},
			InsecureAuth:   true, // Allow authentication over non-TLS connection for testing
			AuthRateLimit:  rateLimit,
			MasterUsername: masterUser,
			MasterPassword: masterPass,
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

// msLogin performs one LOGIN exchange on a fresh connection and returns the
// verbatim response line.
func msLogin(t *testing.T, address, username, password string) string {
	t.Helper()

	client, err := NewManageSieveClient(address)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	if err := client.SendCommand(fmt.Sprintf("LOGIN %q %q", username, password)); err != nil {
		t.Fatalf("LOGIN: %v", err)
	}
	resp, err := client.ReadResponse()
	if err != nil {
		t.Fatalf("LOGIN read: %v", err)
	}
	return resp
}

// masterUsernameVerbs are the two commands that reach the master form. They are
// handled by DIFFERENT functions (AuthenticatePlain and Login), each deriving its
// own rate-limit key, so both must be probed.
var masterUsernameVerbs = []struct {
	name  string
	probe func(t *testing.T, address, username, password string) string
}{
	{"AUTHENTICATE_PLAIN", func(t *testing.T, address, username, password string) string {
		t.Helper()
		return msAuthPlain(t, address, "", username, password)
	}},
	{"LOGIN", msLogin},
}

// masterUsernameRateLimit is Tier 1 only: Tier 2 (IP-only) and the progressive
// delays are disabled so the assertions are on the IP+username bucket alone.
func masterUsernameRateLimit() server.AuthRateLimiterConfig {
	return server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  2 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         0,   // Tier 2 disabled
		DelayStartThreshold:      100, // delays disabled
		CleanupInterval:          1 * time.Minute,
	}
}

// TestManageSieve_MasterUsername_FailuresDoNotLockOutImpersonationTarget proves
// that a failed MASTER password attempt is charged to the master credential,
// never to the account it named.
//
// "user@domain.com@MASTERUSER" needs no secret to submit: the master password is
// checked only after the rate-limit key has already been derived from the
// submitted identity, and that identity canonicalises to the target's address.
// Recording the failure there hands anyone who can reach the port a lockout
// primitive against an arbitrary account (Tier 1 is ip+username, so the block
// lands on every login that account makes from the same observed source IP — a
// shared egress, a NAT, or a proxy that does not forward the client address).
func TestManageSieve_MasterUsername_FailuresDoNotLockOutImpersonationTarget(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	masterUser := fmt.Sprintf("masteruser-%d", time.Now().UnixNano())
	const masterPass = "master_secret_pw"

	for _, verb := range masterUsernameVerbs {
		t.Run(verb.name, func(t *testing.T) {
			address := startManageSieveWithMasterUsername(t, rdb, masterUsernameRateLimit(), masterUser, masterPass)

			// Burn the Tier-1 budget with WRONG master passwords, every attempt
			// naming the victim as the impersonation target.
			for i := 0; i < 3; i++ {
				resp := verb.probe(t, address, account.Email+"@"+masterUser, fmt.Sprintf("wrong-master-pw-%d", i))
				if strings.HasPrefix(resp, "OK") {
					t.Fatalf("attempt %d: a wrong master password must not authenticate, got %q", i+1, resp)
				}
			}

			// The victim must still be able to log in with its OWN password.
			resp := msAuthPlain(t, address, "", account.Email, account.Password)
			if !strings.HasPrefix(resp, "OK") {
				t.Fatalf("impersonation target locked out by failed master-password attempts that merely NAMED it: %q", resp)
			}
			t.Logf("✓ impersonation target still able to log in: %s", resp)
		})
	}
}

// TestManageSieve_MasterUsername_BruteForceIsMeteredAcrossTargets proves the
// other half of the same key defect: because the key follows the named target, an
// attacker gets a FRESH Tier-1 bucket for every target, so the tenant-wide master
// password is never metered no matter how many guesses are made from one IP.
func TestManageSieve_MasterUsername_BruteForceIsMeteredAcrossTargets(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	masterUser := fmt.Sprintf("masteruser-%d", time.Now().UnixNano())
	const masterPass = "master_secret_pw"

	for _, verb := range masterUsernameVerbs {
		t.Run(verb.name, func(t *testing.T) {
			// Control: on an untouched server the master credential authenticates,
			// so the assertion below cannot pass merely because master login is
			// broken.
			control := startManageSieveWithMasterUsername(t, rdb, masterUsernameRateLimit(), masterUser, masterPass)
			if resp := verb.probe(t, control, account.Email+"@"+masterUser, masterPass); !strings.HasPrefix(resp, "OK") {
				t.Fatalf("control: master username login must work, got %q", resp)
			}

			probed := startManageSieveWithMasterUsername(t, rdb, masterUsernameRateLimit(), masterUser, masterPass)

			// Three guesses at the master password, each naming a DIFFERENT target.
			for i := 0; i < 3; i++ {
				target := fmt.Sprintf("nobody-%d-%d@example.com", time.Now().UnixNano(), i)
				resp := verb.probe(t, probed, target+"@"+masterUser, fmt.Sprintf("wrong-master-pw-%d", i))
				if strings.HasPrefix(resp, "OK") {
					t.Fatalf("attempt %d: a wrong master password must not authenticate, got %q", i+1, resp)
				}
			}

			// The master credential must now be blocked — even the CORRECT password
			// must be refused, which is only possible if all three guesses landed in
			// ONE bucket.
			if resp := verb.probe(t, probed, account.Email+"@"+masterUser, masterPass); strings.HasPrefix(resp, "OK") {
				t.Fatalf("master password still usable after 3 recorded failures: varying the impersonation target hands every guess a fresh Tier-1 bucket, so the tenant-wide master password is never metered (got %q)", resp)
			} else {
				t.Logf("✓ master credential blocked after 3 guesses across different targets: %s", resp)
			}
		})
	}
}
