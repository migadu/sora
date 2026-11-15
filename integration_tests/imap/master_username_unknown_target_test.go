//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// masterUsernameFailures reads the IMAP authentication-failure counter of the
// servers started by startIMAPWithMasterUsername.
func masterUsernameFailures() float64 {
	return testutil.ToFloat64(metrics.AuthenticationAttempts.WithLabelValues("imap", "test-master-username-ratelimit-key", "localhost", "failure"))
}

// TestIMAP_MasterUsername_UnknownTargetIsABadCredential proves that the master
// form "user@domain.com@MASTERUSER" with the CORRECT master password and a target
// that has no active account is answered exactly like a wrong master password,
// and counted as a failed authentication, on both commands that reach the master
// form (LOGIN in login.go, AUTHENTICATE PLAIN in sasl.go).
//
// The two probe sequences run against two servers with IDENTICAL configuration so
// the comparison also covers the rate-limiter state: if only one of the two cases
// were recorded as a failure, the sequences would diverge at the block threshold
// even when every individual reply matched.
func TestIMAP_MasterUsername_UnknownTargetIsABadCredential(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	masterUser := fmt.Sprintf("masteruser-%d", time.Now().UnixNano())
	const masterPass = "master_secret_pw"

	for _, verb := range masterUsernameVerbs {
		t.Run(verb.name, func(t *testing.T) {
			// Control: on an untouched server the master credential impersonates a
			// real account, so the comparisons below cannot pass merely because
			// master login is broken.
			control := startIMAPWithMasterUsername(t, rdb, masterUsernameRateLimit(), masterUser, masterPass)
			if resp := verb.probe(t, control, account.Email+"@"+masterUser, masterPass); !strings.HasPrefix(resp, "A001 OK") {
				t.Fatalf("control: master username login must work, got %q", resp)
			}

			correctAddr := startIMAPWithMasterUsername(t, rdb, masterUsernameRateLimit(), masterUser, masterPass)
			wrongAddr := startIMAPWithMasterUsername(t, rdb, masterUsernameRateLimit(), masterUser, masterPass)

			unknown := fmt.Sprintf("nobody-%d@example.com", time.Now().UnixNano())

			// Enough attempts to cross the Tier-1 threshold (3) on both sides.
			const attempts = 5
			for i := 0; i < attempts; i++ {
				before := masterUsernameFailures()
				withMaster := verb.probe(t, correctAddr, unknown+"@"+masterUser, masterPass)
				failures := masterUsernameFailures() - before

				withWrong := verb.probe(t, wrongAddr, unknown+"@"+masterUser, fmt.Sprintf("wrong-master-pw-%d", i))

				if strings.HasPrefix(withMaster, "A001 OK") {
					t.Fatalf("attempt %d: an unknown impersonation target must not authenticate, got %q", i+1, withMaster)
				}
				if withMaster != withWrong {
					t.Fatalf("attempt %d: an unknown target with the correct master password is not answered like a bad credential\n  correct master password: %q\n  wrong master password:   %q", i+1, withMaster, withWrong)
				}
				// The attempts before the block reach the target lookup; each must be
				// counted as a failed authentication.
				if i < 3 && failures != 1 {
					t.Fatalf("attempt %d: sora_authentication_attempts_total{result=\"failure\"} grew by %v, want 1", i+1, failures)
				}
			}
			t.Logf("✓ unknown target answered like a bad credential in all %d attempts", attempts)
		})
	}
}

// TestIMAP_MasterUsername_UnknownTargetConsumesMasterBudget proves the accounting
// half of the same property. Blocked and failed replies are deliberately
// byte-identical, so a reply comparison alone cannot see whether the attempts were
// recorded: an unknown-target attempt that is not recorded leaves the master
// credential usable while a wrong password exhausts it, and that difference IS
// observable by probing the credential afterwards.
func TestIMAP_MasterUsername_UnknownTargetConsumesMasterBudget(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	masterUser := fmt.Sprintf("masteruser-%d", time.Now().UnixNano())
	const masterPass = "master_secret_pw"

	for _, verb := range masterUsernameVerbs {
		t.Run(verb.name, func(t *testing.T) {
			// Control: on an untouched server the master credential impersonates
			// the account, so the assertion below cannot pass merely because
			// master login is broken.
			control := startIMAPWithMasterUsername(t, rdb, masterUsernameRateLimit(), masterUser, masterPass)
			if resp := verb.probe(t, control, account.Email+"@"+masterUser, masterPass); !strings.HasPrefix(resp, "A001 OK") {
				t.Fatalf("control: master username login must work, got %q", resp)
			}

			probed := startIMAPWithMasterUsername(t, rdb, masterUsernameRateLimit(), masterUser, masterPass)

			// Burn the Tier-1 budget with the CORRECT master password and targets
			// that have no account.
			for i := 0; i < 3; i++ {
				unknown := fmt.Sprintf("nobody-%d-%d@example.com", time.Now().UnixNano(), i)
				if resp := verb.probe(t, probed, unknown+"@"+masterUser, masterPass); strings.HasPrefix(resp, "A001 OK") {
					t.Fatalf("attempt %d: an unknown impersonation target must not authenticate, got %q", i+1, resp)
				}
			}

			// The master credential must now be blocked, exactly as three wrong
			// passwords would have left it.
			if resp := verb.probe(t, probed, account.Email+"@"+masterUser, masterPass); strings.HasPrefix(resp, "A001 OK") {
				t.Fatalf("master credential still usable after 3 unknown-target attempts: they are not recorded against it (got %q)", resp)
			} else {
				t.Logf("✓ master credential blocked after 3 unknown-target attempts: %s", resp)
			}
		})
	}
}
