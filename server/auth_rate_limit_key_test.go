package server

import "testing"

// TestAuthRateLimitKey pins the contract every protocol relies on: the same key for
// every submitted form of one account, and a stable, NON-EMPTY key for identities
// that are not addresses (an empty key would merge every unparseable identity — the
// master SASL username among them — into one shared bucket).
func TestAuthRateLimitKey(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     string
	}{
		{"plain address", "user@example.com", "user@example.com"},
		{"upper case", "USER@EXAMPLE.COM", "user@example.com"},
		{"mixed case", "User@Example.Com", "user@example.com"},
		{"plus detail", "user+tag@example.com", "user@example.com"},
		{"plus detail and case", "User+Tag@Example.COM", "user@example.com"},
		{"master username suffix", "user@example.com@admin", "user@example.com"},
		{"suffix and detail", "user+tag@example.com@TOKEN", "user@example.com"},
		{"surrounding space", "  user@example.com  ", "user@example.com"},
		// Not addresses: they keep a bucket of their own.
		{"master sasl username", "proxyuser", "proxyuser"},
		{"master sasl username cased", "ProxyUser", "proxyuser"},
		{"other non-address", "not an address", "not an address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AuthRateLimitKey(tt.username); got != tt.want {
				t.Errorf("AuthRateLimitKey(%q) = %q, want %q", tt.username, got, tt.want)
			}
		})
	}
}

// TestAuthRateLimitKeyWithMaster pins the property the plain key cannot provide:
// "user@domain.com@MASTERUSER" verifies the MASTER password, not the account's, so
// it must never be keyed on the account it names. Keying on the target charges an
// arbitrary account for an attempt that only mentioned it, and hands the caller a
// fresh bucket per target so the tenant-wide master password is never metered.
func TestAuthRateLimitKeyWithMaster(t *testing.T) {
	master := []byte("admin")

	tests := []struct {
		name     string
		username string
		want     string
	}{
		// The master form: keyed on the credential, NOT on "user@example.com".
		{"master form", "user@example.com@admin", "master:admin"},
		{"master form other target", "someone.else@example.com@admin", "master:admin"},
		{"master form with detail", "user+tag@example.com@admin", "master:admin"},
		// Suffix that is not the configured master username (a remotelookup token)
		// is not a local master attempt and keeps the ordinary key.
		{"non-master suffix", "user@example.com@TOKEN", "user@example.com"},
		// Everything else is unchanged.
		{"plain address", "user@example.com", "user@example.com"},
		{"master sasl username", "proxyuser", "proxyuser"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AuthRateLimitKeyWithMaster(tt.username, master); got != tt.want {
				t.Errorf("AuthRateLimitKeyWithMaster(%q) = %q, want %q", tt.username, got, tt.want)
			}
		})
	}

	// Two different targets under the same master credential must share ONE bucket.
	if a, b := AuthRateLimitKeyWithMaster("a@example.com@admin", master), AuthRateLimitKeyWithMaster("b@example.com@admin", master); a != b {
		t.Fatalf("varying the impersonation target produced different keys (%q vs %q): every guess at the master password would get a fresh Tier 1 bucket", a, b)
	}

	// With no master username configured nothing is treated as a master attempt.
	if got := AuthRateLimitKeyWithMaster("user@example.com@admin", nil); got != "user@example.com" {
		t.Errorf("AuthRateLimitKeyWithMaster with no master configured = %q, want %q", got, "user@example.com")
	}
}

// TestMasterAuthRateLimitKey_CannotCollideWithAnAccount guards the namespace: a
// master bucket must not be reachable as a parseable address, or a successful
// login by that account would clear the master credential's failure count.
func TestMasterAuthRateLimitKey_CannotCollideWithAnAccount(t *testing.T) {
	key := MasterAuthRateLimitKey("admin")
	if _, err := NewAddress(key); err == nil {
		t.Fatalf("master key %q parses as an address: a successful login as it would clear the master credential's bucket", key)
	}
	if key == AuthRateLimitKey("user@example.com@admin") {
		t.Fatalf("master key %q equals the impersonation target's key", key)
	}
}

// TestAuthRateLimitKey_DistinctIdentitiesStayDistinct guards the property that makes
// the fallback safe: two different non-address identities must not collapse onto the
// same key, and must never collapse onto the empty key.
func TestAuthRateLimitKey_DistinctIdentitiesStayDistinct(t *testing.T) {
	a := AuthRateLimitKey("proxyuser")
	b := AuthRateLimitKey("otheruser")

	if a == b {
		t.Fatalf("distinct non-address identities collapsed onto one key: %q", a)
	}
	for _, k := range []string{a, b} {
		if k == "" {
			t.Fatal("non-address identity produced an empty key: every unparseable identity would share one rate-limit bucket")
		}
	}
}
