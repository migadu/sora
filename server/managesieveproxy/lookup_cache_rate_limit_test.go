package managesieveproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

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
