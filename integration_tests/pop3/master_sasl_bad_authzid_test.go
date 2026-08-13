//go:build integration

package pop3_test

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
)

// TestPOP3_MasterSASL_BadAuthzIDIsNotAPasswordOracle proves that a REJECTED
// impersonation target does not tell the caller whether the master password was
// right.
//
// A reply reachable only with the correct master password ("Invalid impersonation
// target user format") confirms a guessed tenant-wide credential without ever
// completing an authentication — the same class as the empty-authzid oracle
// already closed. The unknown-target case answers generically already, but it is
// RECORDED against the named target rather than the master credential, so its
// sequence still diverges from a wrong password at the block threshold.
//
// The two probe sequences run against two servers with IDENTICAL configuration so
// the comparison also covers the rate-limiter state.
func TestPOP3_MasterSASL_BadAuthzIDIsNotAPasswordOracle(t *testing.T) {
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
	control := startPOP3WithMasterSASL(t, rdb, rateLimit, saslUser, saslPass)
	if resp := pop3AuthPlain(t, control, account.Email, saslUser, saslPass); !strings.HasPrefix(resp, "+OK") {
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

	// Enough attempts to cross the Tier-1 threshold (3).
	const attempts = 4

	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			// Sequences are collected concurrently: every failed POP3 command is
			// tarpitted for Pop3ErrorDelay (3s) before the reply.
			t.Parallel()

			// One server per password, so each probe sequence gets its own
			// rate-limiter state.
			correctAddr := startPOP3WithMasterSASL(t, rdb, rateLimit, saslUser, saslPass)
			wrongAddr := startPOP3WithMasterSASL(t, rdb, rateLimit, saslUser, saslPass)

			var withMaster, withWrong [attempts]string
			var probeErr [2]error
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				for i := 0; i < attempts && probeErr[0] == nil; i++ {
					withMaster[i], probeErr[0] = pop3AuthPlainErr(correctAddr, target.authzID, saslUser, saslPass)
				}
			}()
			go func() {
				defer wg.Done()
				for i := 0; i < attempts && probeErr[1] == nil; i++ {
					withWrong[i], probeErr[1] = pop3AuthPlainErr(wrongAddr, target.authzID, saslUser, fmt.Sprintf("wrong-master-pw-%d", i))
				}
			}()
			wg.Wait()

			for _, err := range probeErr {
				if err != nil {
					t.Fatalf("probe: %v", err)
				}
			}

			for i := 0; i < attempts; i++ {
				if strings.HasPrefix(withMaster[i], "+OK") {
					t.Fatalf("attempt %d: a rejected impersonation target must not authenticate, got %q", i+1, withMaster[i])
				}
				if withMaster[i] != withWrong[i] {
					t.Fatalf("attempt %d: response is a master-password oracle\n  correct master password: %q\n  wrong master password:   %q", i+1, withMaster[i], withWrong[i])
				}
			}
		})
	}
}

// TestPOP3_MasterSASL_RejectedAuthzIDConsumesMasterBudget proves the accounting
// half of the same property. Blocked and failed replies are deliberately
// byte-identical, so a message comparison alone cannot see whether the two cases
// were recorded alike: an attempt that is not recorded leaves the master
// credential usable while a wrong password exhausts it, and that difference IS
// observable by probing the credential afterwards.
//
// The failure must land in the master credential's own bucket — never the named
// target's, which would charge an account for merely having been named.
func TestPOP3_MasterSASL_RejectedAuthzIDConsumesMasterBudget(t *testing.T) {
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
			// Every failed POP3 command is tarpitted for Pop3ErrorDelay (3s).
			t.Parallel()

			// Control: on an untouched server the master credential impersonates
			// the account, so the assertion below cannot pass merely because
			// master SASL is broken.
			control := startPOP3WithMasterSASL(t, rdb, rateLimit, saslUser, saslPass)
			if resp := pop3AuthPlain(t, control, account.Email, saslUser, saslPass); !strings.HasPrefix(resp, "+OK") {
				t.Fatalf("control: master SASL impersonation must work, got %q", resp)
			}

			probed := startPOP3WithMasterSASL(t, rdb, rateLimit, saslUser, saslPass)

			// Burn the Tier-1 budget with the CORRECT master password and a
			// target that will be rejected.
			for i := 0; i < 3; i++ {
				if resp := pop3AuthPlain(t, probed, target.authzID, saslUser, saslPass); strings.HasPrefix(resp, "+OK") {
					t.Fatalf("attempt %d: a rejected impersonation target must not authenticate, got %q", i+1, resp)
				}
			}

			// The master credential must now be blocked, exactly as three wrong
			// passwords would have left it.
			if resp := pop3AuthPlain(t, probed, account.Email, saslUser, saslPass); strings.HasPrefix(resp, "+OK") {
				t.Fatalf("master SASL still usable after 3 rejected-target probes with the correct master password: the probes are not recorded against the master credential, so the reply is an oracle at the block threshold (got %q)", resp)
			} else {
				t.Logf("✓ master credential blocked after 3 rejected-target probes: %s", resp)
			}
		})
	}
}
