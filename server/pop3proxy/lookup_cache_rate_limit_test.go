package pop3proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/lookupcache"
	"github.com/migadu/sora/server"
)

// TestCachedLoginFromBlockedIPIsRefused verifies that a login answered from the
// lookup cache is refused while its source address is blocked, and that it does not
// lift the block. Regression test for #351: the cache shortcut ran before
// CanAttemptAuthWithProxy and recorded a success, which deleted the address's block.
func TestCachedLoginFromBlockedIPIsRefused(t *testing.T) {
	ctx := context.Background()

	const clientIP = "203.0.113.7"
	limiter := server.NewAuthRateLimiter("pop3_proxy", "test", "test-host", server.AuthRateLimiterConfig{
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

	cache := newPOP3TestLookupCache(t)
	cache.Set("test", "user@example.com", &lookupcache.CacheEntry{
		AccountID:      42,
		PasswordDigest: lookupcache.NewPasswordDigest("secret"),
		Result:         lookupcache.AuthSuccess,
	})
	srv := &POP3ProxyServer{
		name:                       "test",
		hostname:                   "test-host",
		connManager:                newPOP3TestConnManager(t, "127.0.0.1:1", 500*time.Millisecond),
		lookupCache:                cache,
		authLimiter:                limiter,
		positiveRevalidationWindow: 30 * time.Second,
	}

	client, remote := net.Pipe()
	defer client.Close()
	defer remote.Close()
	sess := &POP3ProxySession{
		server:       srv,
		clientConn:   client,
		listenerConn: client,
		ctx:          ctx,
		proxyInfo:    &server.ProxyProtocolInfo{SrcIP: clientIP},
	}

	err := sess.authenticate("user@example.com", "secret")
	var rle *server.RateLimitError
	if !errors.As(err, &rle) || rle.Reason != "ip_blocked" {
		t.Errorf("cached login from a blocked address: err = %v, want an ip_blocked RateLimitError", err)
	}
	if !limiter.IsIPBlocked(clientAddr) {
		t.Error("the cached login lifted the address's block")
	}
}
