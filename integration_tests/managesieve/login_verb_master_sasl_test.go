//go:build integration

package managesieve

import (
	"strings"
	"testing"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
)

// TestManageSieve_LoginVerb_BareMasterSASLIsRejected pins the fleet-wide rule that master
// credentials authenticate only when an impersonation target is named.
//
// The ManageSieve LOGIN verb had a master-SASL branch that treated
// LOGIN "<master_sasl_username>" "<master_sasl_password>" as a successful login as the
// account whose address equals the master SASL username — with the master password, not the
// account's own. IMAP and POP3 do not allow that: after the RFC 4616 fix, a master
// submission that names no distinct target falls through to regular authentication. LOGIN
// carries no authorization identity at all, so a bare master credential there names no
// target and must not be a master login.
//
// This is a capability-consistency fix, not an escalation (the master can impersonate that
// account by naming it), but a backend that accepts a shape the others reject is exactly the
// kind of divergence that makes an auth surface hard to reason about.
func TestManageSieve_LoginVerb_BareMasterSASLIsRejected(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	// The master SASL username IS a real account address, so the only thing that could let
	// the bare LOGIN through is the master-SASL branch treating the master password as valid.
	account := common.CreateTestAccount(t, rdb)
	saslUser := account.Email
	const saslPass = "login_verb_master_sasl_secret"

	address := startManageSieveWithMasterSASL(t, rdb, server.AuthRateLimiterConfig{Enabled: false}, saslUser, saslPass)

	// Bare LOGIN with the master SASL credential and no target: must be refused.
	if resp := msLogin(t, address, saslUser, saslPass); !strings.HasPrefix(resp, "NO") {
		t.Errorf("LOGIN with a bare master SASL credential authenticated (%q) — master credentials must "+
			"name an impersonation target, as they now do on IMAP and POP3", resp)
	}

	// Control: the account still logs in with its OWN password via LOGIN (regular auth),
	// so the fix rejected only the master-password shortcut, not the account itself.
	if resp := msLogin(t, address, account.Email, account.Password); !strings.HasPrefix(resp, "OK") {
		t.Errorf("the account can no longer log in with its own password via LOGIN: %q", resp)
	}
}
