//go:build integration

package managesieve

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
)

// TestManageSieve_MasterSASL_BadAuthzIDIsNotAPasswordOracle proves that a
// REJECTED impersonation target does not tell the caller whether the master
// password was right.
//
// A reply reachable only with the correct master password ("Invalid impersonation
// target user format", "Impersonation target user not found") confirms a guessed
// tenant-wide credential without ever completing an authentication — the same
// class as the empty-authzid oracle already closed.
//
// The two probe sequences run against two servers with IDENTICAL configuration so
// the comparison also covers the rate-limiter state: if only one of the two cases
// were recorded as a failure, the sequences would diverge at the block threshold
// even when every individual message matched.
func TestManageSieve_MasterSASL_BadAuthzIDIsNotAPasswordOracle(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	saslUser := fmt.Sprintf("proxyuser-%d", time.Now().UnixNano())
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

	// Control: master SASL impersonation of a REAL target works, so the
	// comparisons below cannot pass merely because master SASL is broken.
	control := startManageSieveWithMasterSASL(t, rdb, rateLimit, saslUser, saslPass)
	if resp := msAuthPlain(t, control, account.Email, saslUser, saslPass); !strings.HasPrefix(resp, "OK") {
		t.Fatalf("control: master SASL impersonation must work, got %q", resp)
	}

	targets := []struct {
		name    string
		authzID string
	}{
		// Does not parse as an address.
		{"malformed_authzid", "not-an-address"},
		// Parses, but no such account.
		{"unknown_authzid", fmt.Sprintf("nobody-%d@example.com", time.Now().UnixNano())},
	}

	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			// One server per password, so each probe sequence gets its own
			// rate-limiter state.
			correctAddr := startManageSieveWithMasterSASL(t, rdb, rateLimit, saslUser, saslPass)
			wrongAddr := startManageSieveWithMasterSASL(t, rdb, rateLimit, saslUser, saslPass)

			// Enough attempts to cross the Tier-1 threshold (3) on both sides.
			const attempts = 5

			for i := 0; i < attempts; i++ {
				withMaster := msAuthPlain(t, correctAddr, target.authzID, saslUser, saslPass)
				withWrong := msAuthPlain(t, wrongAddr, target.authzID, saslUser, fmt.Sprintf("wrong-master-pw-%d", i))

				if strings.HasPrefix(withMaster, "OK") {
					t.Fatalf("attempt %d: a rejected impersonation target must not authenticate, got %q", i+1, withMaster)
				}
				if withMaster != withWrong {
					t.Fatalf("attempt %d: response is a master-password oracle\n  correct master password: %q\n  wrong master password:   %q", i+1, withMaster, withWrong)
				}
			}
		})
	}
}

// TestManageSieve_MasterSASL_RejectedAuthzIDConsumesMasterBudget proves the
// accounting half of the same property. Blocked and failed replies are
// deliberately byte-identical, so a message comparison alone cannot see whether
// the two cases were recorded alike: an attempt that is not recorded leaves the
// master credential usable while a wrong password exhausts it, and that
// difference IS observable by probing the credential afterwards.
//
// The failure must land in the master credential's own bucket — never the named
// target's, which would charge an account for merely having been named.
func TestManageSieve_MasterSASL_RejectedAuthzIDConsumesMasterBudget(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

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

	targets := []struct {
		name    string
		authzID string
	}{
		{"malformed_authzid", "not-an-address"},
		{"unknown_authzid", fmt.Sprintf("nobody-%d@example.com", time.Now().UnixNano())},
	}

	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			// Control: on an untouched server the master credential impersonates
			// the account, so the assertion below cannot pass merely because
			// master SASL is broken.
			control := startManageSieveWithMasterSASL(t, rdb, rateLimit, saslUser, saslPass)
			if resp := msAuthPlain(t, control, account.Email, saslUser, saslPass); !strings.HasPrefix(resp, "OK") {
				t.Fatalf("control: master SASL impersonation must work, got %q", resp)
			}

			probed := startManageSieveWithMasterSASL(t, rdb, rateLimit, saslUser, saslPass)

			// Burn the Tier-1 budget with the CORRECT master password and a
			// target that will be rejected.
			for i := 0; i < 3; i++ {
				if resp := msAuthPlain(t, probed, target.authzID, saslUser, saslPass); strings.HasPrefix(resp, "OK") {
					t.Fatalf("attempt %d: a rejected impersonation target must not authenticate, got %q", i+1, resp)
				}
			}

			// The master credential must now be blocked, exactly as three wrong
			// passwords would have left it.
			if resp := msAuthPlain(t, probed, account.Email, saslUser, saslPass); strings.HasPrefix(resp, "OK") {
				t.Fatalf("master SASL still usable after 3 rejected-target probes with the correct master password: the probes are not recorded against the master credential, so the reply is an oracle at the block threshold (got %q)", resp)
			} else {
				t.Logf("✓ master credential blocked after 3 rejected-target probes: %s", resp)
			}
		})
	}
}
