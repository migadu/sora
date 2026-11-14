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

// TestManageSieve_MasterUsernameRejectedTargetDoesNotResetTheBlock covers the ordering of
// the rate-limiter records on the master-USERNAME verb (user@domain@MASTERUSER).
//
// A success does not merely fail to increment: it clears this key's Tier-1 count AND, via
// clearFailureTracking, the source IP's Tier-2 count and any active block. Recording the
// success as soon as the master password matched - before the impersonation target is
// resolved - therefore made a correct master password plus a non-existent target write
// success-then-failure on every attempt. The count returned to 1 each time, so the master
// credential could never reach the block threshold on this verb, and the whole-IP block
// could be cleared on demand by looping it.
//
// The observable contract: N rejected-target attempts must block the master credential,
// exactly as N wrong-password attempts do.
func TestManageSieve_MasterUsernameRejectedTargetDoesNotResetTheBlock(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	rdb := common.SetupTestDatabase(t)
	account := common.CreateTestAccount(t, rdb)

	const masterUser = "masteruser"
	const masterPass = "master_secret_pw"

	// Tier 1 blocks the (ip, username) pair after 3 failures.
	rateLimit := server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  2 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         0,   // Tier 2 disabled: this test is about the Tier-1 key
		DelayStartThreshold:      100, // delays disabled so the test does not sleep
		CleanupInterval:          1 * time.Minute,
	}

	address := startManageSieveWithMasterUsername(t, rdb, rateLimit, masterUser, masterPass)

	// Three attempts with the correct master password naming targets that do not exist.
	// Each is a genuine failed authentication and must be charged to the master credential.
	for i := 0; i < 3; i++ {
		target := fmt.Sprintf("ghost%d@example.com", i)
		resp := msAuthPlain(t, address, "", target+"@"+masterUser, masterPass)
		if strings.HasPrefix(resp, "OK") {
			t.Fatalf("attempt %d: impersonation of a non-existent target succeeded: %q", i, resp)
		}
	}

	// The master credential must now be blocked, the same as after three wrong passwords.
	// A real target is used here so the only thing that can let it through is the missing
	// block; the reply is deliberately identical to a bad-credential reply either way.
	resp := msAuthPlain(t, address, "", account.Email+"@"+masterUser, masterPass)
	if strings.HasPrefix(resp, "OK") {
		t.Errorf("master credential still usable after 3 rejected-target attempts (got %q) - "+
			"recording the success before the target is resolved lets those attempts reset the "+
			"counter, so this verb can never reach the block threshold", resp)
	}
}
