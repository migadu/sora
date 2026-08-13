//go:build integration

package imap_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
)

// TestIMAP_RateLimiting_Tier1_KeyIsCanonical proves the Tier-1 (IP+username) key is
// canonicalised at the CHECK site, not only at the record site.
//
// LOGIN used to call CanAttemptAuthWithProxy with the raw client-supplied string
// while every RecordAuthAttempt* call used addressParsed.BaseAddress(). Because
// server.NewAddress lowercases and BaseAddress strips "+detail", an attacker could
// vary the case or append a different +tag on every attempt: no check key ever
// repeated, so Tier 1 never engaged (a probe got 12 consecutive attempts allowed
// while the recorded block ratcheted up on the victim's canonical address).
//
// Every attempt below is a different raw string for the SAME account, so with a
// canonical check key the Tier-1 budget is shared and the attacker is stopped.
func TestIMAP_RateLimiting_Tier1_KeyIsCanonical(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Tier 1 only; Tier 2 and progressive delays disabled so the assertion is on
	// blocking alone and never on timing.
	srv, account := setupIMAPServerWithRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  2 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         0,   // Tier 2 disabled
		DelayStartThreshold:      100, // delays disabled
		CleanupInterval:          1 * time.Minute,
	})
	defer srv.Close()

	withTag := func(tag string) string {
		return strings.Replace(account.Email, "@", "+"+tag+"@", 1)
	}

	login := func(address, password string) error {
		c, err := imapclient.DialInsecure(srv.Address, nil)
		if err != nil {
			t.Fatalf("dial failed: %v", err)
		}
		defer c.Close()
		return c.Login(address, password).Wait()
	}

	// Three failures, each under a DIFFERENT raw string for the same account.
	variants := []string{
		strings.ToUpper(account.Email), // case variation
		withTag("t1"),                  // +detail variation
		withTag("t2"),                  // another +detail variation
	}
	for i, variant := range variants {
		if err := login(variant, fmt.Sprintf("wrong-password-%d", i)); err == nil {
			t.Fatalf("attempt %d (%q): login should have failed", i+1, variant)
		}
	}

	// A fourth, again-unseen raw form of the same account — with the CORRECT
	// password. It must be refused: the three failures above belong to the same
	// canonical key. Before the fix this logged in, which is the bypass.
	if err := login(withTag("t3"), account.Password); err == nil {
		t.Fatal("login allowed after 3 failures for the same account: Tier 1 is bypassable by varying case or +detail")
	} else {
		t.Logf("✓ Tier 1 blocked the canonical key regardless of the submitted form: %v", err)
	}
}
