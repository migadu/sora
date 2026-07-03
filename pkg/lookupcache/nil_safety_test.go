package lookupcache

import (
	"testing"
)

// TestNilReceiverSafety verifies that a nil *LookupCache (lookup cache disabled
// in config) is safe to use. Regression test for the IMAP proxy panic where
// authenticateUser called Get/Set on a nil cache and every authentication
// attempt crashed (imapproxy review H1, 2026-07-03).
func TestNilReceiverSafety(t *testing.T) {
	var c *LookupCache // nil: cache disabled

	entry, found := c.Get("proxy", "user@example.com")
	if entry != nil || found {
		t.Errorf("nil cache Get: expected (nil, false), got (%v, %v)", entry, found)
	}

	// Must not panic
	c.Set("proxy", "user@example.com", &CacheEntry{AccountID: 1})

	// Must not panic
	c.Invalidate("proxy:user@example.com")

	// Must not panic
	c.InvalidateUser("proxy", "user@example.com")
}
