package managesieveproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/consts"
	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server"
	"github.com/migadu/sora/server/proxy"
)

// TestCachedLoginFromBlockedIPIsRefused verifies that a login answered from the
// lookup cache is refused while its source address is blocked, and that it does not
// lift the block. Regression test for #351: the cache shortcut ran before
// CanAttemptAuthWithProxy and recorded a success, which deleted the address's block.
func TestCachedLoginFromBlockedIPIsRefused(t *testing.T) {
	ctx := context.Background()

	const clientIP = "203.0.113.7"
	limiter := server.NewAuthRateLimiter("managesieve_proxy", "test", "test-host", server.AuthRateLimiterConfig{
		Enabled:          true,
		MaxAttemptsPerIP: 3,
		IPBlockDuration:  time.Hour,
		IPWindowDuration: time.Hour,
		CleanupInterval:  time.Hour,
	})
	defer limiter.Stop()
	clientAddr := &server.StringAddr{Addr: clientIP}
	for i := 0; i < 3; i++ {
		limiter.RecordAuthAttempt(ctx, clientAddr, fmt.Sprintf("guess%d@example.com", i), false)
	}
	if !limiter.IsIPBlocked(clientAddr) {
		t.Fatal("setup: address is not blocked")
	}

	cache := newMSTestLookupCache(t)
	cache.Set("test", "user@example.com", &lookupcache.CacheEntry{
		AccountID:      42,
		PasswordDigest: lookupcache.NewPasswordDigest("secret"),
		Result:         lookupcache.AuthSuccess,
	})
	cm, err := proxy.NewConnectionManager([]string{"127.0.0.1:1"}, 4190, false, false, false, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{
		name:                       "test",
		hostname:                   "test-host",
		connManager:                cm,
		lookupCache:                cache,
		authLimiter:                limiter,
		positiveRevalidationWindow: 30 * time.Second,
	}

	client, remote := net.Pipe()
	defer client.Close()
	defer remote.Close()
	sess := &Session{
		server:       srv,
		clientConn:   client,
		listenerConn: client,
		ctx:          ctx,
		proxyInfo:    &server.ProxyProtocolInfo{SrcIP: clientIP},
	}

	err = sess.authenticateUser("user@example.com", "secret", time.Now())
	var rle *server.RateLimitError
	if !errors.As(err, &rle) || rle.Reason != "ip_blocked" {
		t.Errorf("cached login from a blocked address: err = %v, want an ip_blocked RateLimitError", err)
	}
	if sess.accountID != 0 {
		t.Errorf("accountID = %d, want 0: the session must not be authenticated", sess.accountID)
	}
	if !limiter.IsIPBlocked(clientAddr) {
		t.Error("the cached login lifted the address's block")
	}
}

// TestCachedFailuresCountTowardsTheBlock verifies that a login refused from the lookup
// cache is charged to the rate limiter like any other failed login, as the IMAP and
// POP3 proxies do. The ManageSieve proxy answered a different password on a fresh
// positive entry, and the same password as a negative entry, without recording a
// failure, so within positive_revalidation_window of a user's login an address could
// test passwords against the cached digest without ever being delayed or blocked.
func TestCachedFailuresCountTowardsTheBlock(t *testing.T) {
	const clientIP = "203.0.113.9"
	const maxAttempts = 3

	tests := []struct {
		name  string
		entry *lookupcache.CacheEntry
		guess func(i int) string
	}{
		{
			name: "different password on a fresh positive entry",
			entry: &lookupcache.CacheEntry{
				AccountID:      42,
				PasswordDigest: lookupcache.NewPasswordDigest("secret"),
				Result:         lookupcache.AuthSuccess,
			},
			guess: func(i int) string { return fmt.Sprintf("guess%d", i) },
		},
		{
			name: "same password as a negative entry",
			entry: &lookupcache.CacheEntry{
				PasswordDigest: lookupcache.NewPasswordDigest("wrong"),
				Result:         lookupcache.AuthFailed,
				IsNegative:     true,
			},
			guess: func(int) string { return "wrong" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			limiter := server.NewAuthRateLimiter("managesieve_proxy", "test", "test-host", server.AuthRateLimiterConfig{
				Enabled:          true,
				MaxAttemptsPerIP: maxAttempts,
				IPBlockDuration:  time.Hour,
				IPWindowDuration: time.Hour,
				CleanupInterval:  time.Hour,
			})
			defer limiter.Stop()

			cache := newMSTestLookupCache(t)
			cache.Set("test", "user@example.com", tt.entry)
			cm, err := proxy.NewConnectionManager([]string{"127.0.0.1:1"}, 4190, false, false, false, 500*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			srv := &Server{
				name:                       "test",
				hostname:                   "test-host",
				connManager:                cm,
				lookupCache:                cache,
				authLimiter:                limiter,
				positiveRevalidationWindow: 30 * time.Second,
			}
			client, remote := net.Pipe()
			defer client.Close()
			defer remote.Close()
			sess := &Session{
				server:       srv,
				clientConn:   client,
				listenerConn: client,
				ctx:          ctx,
				proxyInfo:    &server.ProxyProtocolInfo{SrcIP: clientIP},
			}

			for i := 0; i < maxAttempts; i++ {
				if err := sess.authenticateUser("user@example.com", tt.guess(i), time.Now()); !errors.Is(err, consts.ErrAuthenticationFailed) {
					t.Fatalf("attempt %d: err = %v, want ErrAuthenticationFailed from the cache", i+1, err)
				}
			}

			if !limiter.IsIPBlocked(&server.StringAddr{Addr: clientIP}) {
				t.Errorf("%d failed logins answered from the cache did not block the address", maxAttempts)
			}
			err = sess.authenticateUser("user@example.com", tt.guess(maxAttempts), time.Now())
			var rle *server.RateLimitError
			if !errors.As(err, &rle) {
				t.Errorf("attempt after the limit: err = %v, want a RateLimitError", err)
			}
		})
	}
}
