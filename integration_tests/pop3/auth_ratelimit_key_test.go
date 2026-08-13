//go:build integration

package pop3_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/migadu/sora/integration_tests/common"
	"github.com/migadu/sora/server"
)

// TestPOP3_RateLimiting_Tier1_KeyIsCanonical proves the Tier-1 (IP+username) key is
// canonicalised consistently: POP3 checked the raw submitted username but recorded
// failures under userAddress.FullAddress() (lowercased, +detail kept), so varying
// the case or the +detail gave every attempt a fresh check key and Tier 1 never
// engaged.
func TestPOP3_RateLimiting_Tier1_KeyIsCanonical(t *testing.T) {
	common.SkipIfDatabaseUnavailable(t)

	// Tier 1 only; Tier 2 and progressive delays disabled so the assertion is on
	// blocking alone and never on timing. Empty master SASL credentials keep the
	// master path out of this test.
	srv, account := setupPOP3ServerWithMasterSASLRateLimiting(t, server.AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 3,
		IPUsernameBlockDuration:  2 * time.Minute,
		IPUsernameWindowDuration: 5 * time.Minute,
		MaxAttemptsPerIP:         0,   // Tier 2 disabled
		DelayStartThreshold:      100, // delays disabled
		CleanupInterval:          1 * time.Minute,
	}, "", "")
	defer srv.Close()

	withTag := func(tag string) string {
		return strings.Replace(account.Email, "@", "+"+tag+"@", 1)
	}

	login := func(username, password string) string {
		client, err := NewPOP3Client(srv.Address)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer client.Close()

		if err := client.SendCommand("USER " + username); err != nil {
			t.Fatalf("USER: %v", err)
		}
		if _, err := client.ReadResponse(); err != nil {
			t.Fatalf("USER read: %v", err)
		}
		if err := client.SendCommand("PASS " + password); err != nil {
			t.Fatalf("PASS: %v", err)
		}
		resp, err := client.ReadResponse()
		if err != nil {
			t.Fatalf("PASS read: %v", err)
		}
		return resp
	}

	// Three failures, each under a DIFFERENT raw string for the same account.
	variants := []string{
		strings.ToUpper(account.Email), // case variation
		withTag("t1"),                  // +detail variation
		withTag("t2"),                  // another +detail variation
	}
	for i, variant := range variants {
		if resp := login(variant, fmt.Sprintf("wrong-password-%d", i)); strings.HasPrefix(resp, "+OK") {
			t.Fatalf("attempt %d (%q): login should have failed, got %q", i+1, variant, resp)
		}
	}

	// A fourth, again-unseen raw form of the same account — with the CORRECT
	// password. It must be refused: the failures above belong to the same
	// canonical key.
	if resp := login(withTag("t3"), account.Password); strings.HasPrefix(resp, "+OK") {
		t.Fatalf("login allowed after 3 failures for the same account: Tier 1 is bypassable by varying case or +detail, got %q", resp)
	} else {
		t.Logf("✓ Tier 1 blocked the canonical key regardless of the submitted form: %s", resp)
	}
}
