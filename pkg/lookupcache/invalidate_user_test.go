package lookupcache

import (
	"context"
	"testing"
	"time"
)

func invalidateTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Second)
}

// TestInvalidateUserKeyParity verifies that InvalidateUser removes exactly the
// entry that Get/Set address, including for token-style usernames and for an
// empty server name (where makeKey falls back to the bare username).
// Regression test for the invalidation-key mismatch where proxies invalidated
// with the resolved email while entries were keyed on the submitted username
// (imapproxy review M2, 2026-07-03).
func TestInvalidateUserKeyParity(t *testing.T) {
	c := New(5*time.Minute, 1*time.Minute, 100, 5*time.Minute, 30*time.Second)
	defer func() {
		ctx, cancel := invalidateTestContext()
		defer cancel()
		_ = c.Stop(ctx)
	}()

	cases := []struct {
		name       string
		serverName string
		username   string
	}{
		{"plain address", "proxy-1", "user@example.com"},
		{"token suffix", "proxy-1", "user@example.com@TOKEN"},
		{"master suffix", "proxy-1", "user@example.com@MASTER"},
		{"plus detail", "proxy-1", "user+folder@example.com"},
		{"empty server name", "", "user@example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c.Set(tc.serverName, tc.username, &CacheEntry{
				AccountID:    42,
				PasswordHash: HashPassword("secret"),
				Result:       AuthSuccess,
			})
			if _, found := c.Get(tc.serverName, tc.username); !found {
				t.Fatal("entry not found immediately after Set")
			}

			c.InvalidateUser(tc.serverName, tc.username)

			if _, found := c.Get(tc.serverName, tc.username); found {
				t.Errorf("entry still present after InvalidateUser(%q, %q)", tc.serverName, tc.username)
			}
		})
	}
}

// TestInvalidateResolvedUsernameMisses documents WHY InvalidateUser must use
// the submitted username: invalidating with the resolved base address does NOT
// remove an entry keyed on the token form.
func TestInvalidateResolvedUsernameMisses(t *testing.T) {
	c := New(5*time.Minute, 1*time.Minute, 100, 5*time.Minute, 30*time.Second)
	defer func() {
		ctx, cancel := invalidateTestContext()
		defer cancel()
		_ = c.Stop(ctx)
	}()

	submitted := "user@example.com@TOKEN"
	resolved := "user@example.com"

	c.Set("proxy-1", submitted, &CacheEntry{AccountID: 42, Result: AuthSuccess})

	// The old (buggy) invalidation pattern: resolved address
	c.InvalidateUser("proxy-1", resolved)
	if _, found := c.Get("proxy-1", submitted); !found {
		t.Fatal("entry unexpectedly removed by resolved-address invalidation")
	}

	// The correct invalidation: submitted username
	c.InvalidateUser("proxy-1", submitted)
	if _, found := c.Get("proxy-1", submitted); found {
		t.Error("entry still present after submitted-username invalidation")
	}
}
