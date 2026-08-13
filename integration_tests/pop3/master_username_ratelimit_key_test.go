//go:build integration

package pop3_test

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
	"github.com/migadu/sora/server/pop3"
	"github.com/migadu/sora/storage"
)

// startPOP3WithMasterUsername starts a POP3 backend configured with the
// "user@domain.com@MASTERUSER" master form (master_username/master_password).
// That form names the impersonation target INSIDE the authentication identity,
// so its canonical rate-limit key (server.AuthRateLimitKey) is the TARGET's
// address — which is exactly the key a master-credential attempt must not use.
func startPOP3WithMasterUsername(t *testing.T, rdb *resilient.ResilientDatabase, rateLimit server.AuthRateLimiterConfig, masterUser, masterPass string) string {
	t.Helper()

	address := common.GetRandomAddress(t)
	srv, err := pop3.New(
		context.Background(),
		"test-master-username-ratelimit-key",
		"localhost",
		address,
		&storage.S3Storage{},
		rdb,
		nil, // uploadWorker
		nil, // cache
		pop3.POP3ServerOptions{
			InsecureAuth:   true, // Allow PLAIN auth (no TLS in tests)
			Config:         &config.Config{},
			AuthRateLimit:  rateLimit,
			MasterUsername: masterUser,
			MasterPassword: masterPass,
		},
	)
	if err != nil {
		t.Fatalf("Failed to create POP3 server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() { srv.Start(errChan) }()
	time.Sleep(100 * time.Millisecond)
	t.Cleanup(func() { srv.Close() })

	return address
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

// TestPOP3_MasterUsername_FailuresDoNotLockOutImpersonationTarget proves that a
// failed MASTER password attempt is charged to the master credential, never to
// the account it named.
//
// "user@domain.com@MASTERUSER" needs no secret to submit: the master password is
// checked only after the rate-limit key has already been derived from the
// submitted identity, and that identity canonicalises to the target's address.
// Recording the failure there hands anyone who can reach the port a lockout
// primitive against an arbitrary account (Tier 1 is ip+username, so the block
// lands on every login that account makes from the same observed source IP — a
// shared egress, a NAT, or a proxy that does not forward the client address).
func TestPOP3_MasterUsername_FailuresDoNotLockOutImpersonationTarget(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	masterUser := fmt.Sprintf("masteruser-%d", time.Now().UnixNano())
	const masterPass = "master_secret_pw"

	address := startPOP3WithMasterUsername(t, rdb, masterUsernameRateLimit(), masterUser, masterPass)

	// Burn the Tier-1 budget with WRONG master passwords, every attempt naming
	// the victim as the impersonation target.
	for i := 0; i < 3; i++ {
		resp := pop3UserPass(t, address, account.Email+"@"+masterUser, fmt.Sprintf("wrong-master-pw-%d", i))
		if strings.HasPrefix(resp, "+OK") {
			t.Fatalf("attempt %d: a wrong master password must not authenticate, got %q", i+1, resp)
		}
	}

	// The victim must still be able to log in with its OWN password.
	resp := pop3UserPass(t, address, account.Email, account.Password)
	if !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("impersonation target locked out by failed master-password attempts that merely NAMED it: %q", resp)
	}
	t.Logf("✓ impersonation target still able to log in: %s", resp)
}

// TestPOP3_MasterUsername_BruteForceIsMeteredAcrossTargets proves the other half
// of the same key defect: because the key follows the named target, an attacker
// gets a FRESH Tier-1 bucket for every target, so the tenant-wide master
// password is never metered no matter how many guesses are made from one IP.
func TestPOP3_MasterUsername_BruteForceIsMeteredAcrossTargets(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	masterUser := fmt.Sprintf("masteruser-%d", time.Now().UnixNano())
	const masterPass = "master_secret_pw"

	// Control: on an untouched server the master credential authenticates, so the
	// assertion below cannot pass merely because master login is broken.
	control := startPOP3WithMasterUsername(t, rdb, masterUsernameRateLimit(), masterUser, masterPass)
	if resp := pop3UserPass(t, control, account.Email+"@"+masterUser, masterPass); !strings.HasPrefix(resp, "+OK") {
		t.Fatalf("control: master username login must work, got %q", resp)
	}

	probed := startPOP3WithMasterUsername(t, rdb, masterUsernameRateLimit(), masterUser, masterPass)

	// Three guesses at the master password, each naming a DIFFERENT target.
	for i := 0; i < 3; i++ {
		target := fmt.Sprintf("nobody-%d-%d@example.com", time.Now().UnixNano(), i)
		resp := pop3UserPass(t, probed, target+"@"+masterUser, fmt.Sprintf("wrong-master-pw-%d", i))
		if strings.HasPrefix(resp, "+OK") {
			t.Fatalf("attempt %d: a wrong master password must not authenticate, got %q", i+1, resp)
		}
	}

	// The master credential must now be blocked — even the CORRECT password must
	// be refused, which is only possible if all three guesses landed in ONE bucket.
	if resp := pop3UserPass(t, probed, account.Email+"@"+masterUser, masterPass); strings.HasPrefix(resp, "+OK") {
		t.Fatalf("master password still usable after 3 recorded failures: varying the impersonation target hands every guess a fresh Tier-1 bucket, so the tenant-wide master password is never metered (got %q)", resp)
	} else {
		t.Logf("✓ master credential blocked after 3 guesses across different targets: %s", resp)
	}
}
