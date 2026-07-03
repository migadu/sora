package lmtpproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/lookupcache"
)

// TestLMTPInvalidateLookupCacheUsesSubmittedAddress verifies that
// invalidateLookupCache removes the entry keyed by the SUBMITTED recipient
// address (originalAddress), not the remotelookup-resolved one, and that it
// uses the same key derivation as Get/Set (InvalidateUser). Companion to the
// IMAP/POP3/ManageSieve proxy invalidation tests.
func TestLMTPInvalidateLookupCacheUsesSubmittedAddress(t *testing.T) {
	cache := lookupcache.New(5*time.Minute, time.Minute, 100, time.Minute, 0)
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
		defer stopCancel()
		cache.Stop(stopCtx)
	}()

	const serverName = "lmtp-proxy-1"
	const submitted = "orig@example.com"

	cache.Set(serverName, submitted, &lookupcache.CacheEntry{
		AccountID:     42,
		ActualEmail:   "resolved@other.example",
		ServerAddress: "10.0.0.1:24",
		Result:        lookupcache.AuthSuccess,
	})
	if _, found := cache.Get(serverName, submitted); !found {
		t.Fatal("expected cache entry before invalidation")
	}

	clientConn, _ := net.Pipe()
	defer clientConn.Close()
	sess := &Session{
		server:          &Server{name: serverName, lookupCache: cache},
		clientConn:      clientConn,
		originalAddress: submitted,
		username:        "resolved@other.example", // resolution must not affect the key
		ctx:             context.Background(),
	}

	sess.invalidateLookupCache("test")

	if _, found := cache.Get(serverName, submitted); found {
		t.Fatal("cache entry for the submitted address survived invalidation")
	}
}
