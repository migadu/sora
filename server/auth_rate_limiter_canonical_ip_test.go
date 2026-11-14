package server

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// The client address reaches the auth rate limiter as text: the PROXY v1
// header, IMAP ID x-originating-ip and XCLIENT ADDR are kept as the peer wrote
// them, and a peer's gossip carries the key it counted under. One client can
// therefore be spelled several ways, and each spelling must count, block and
// delay as the one address it is.
var equivalentClientSpellings = []struct {
	name string
	a, b string // two spellings of one client, port optional
}{
	{"IPv4 and its IPv4-mapped IPv6 form", "192.0.2.1", "::ffff:192.0.2.1"},
	{"IPv4-mapped with port and IPv4 with port", "[::ffff:192.0.2.2]:4000", "192.0.2.2:5000"},
	{"IPv6 compressed and upper-case uncompressed", "2001:db8::1", "[2001:0DB8:0:0:0:0:0:1]:4000"},
	{"IPv6 upper-case and lower-case", "[2001:DB8::2]:4000", "2001:db8::2"},
}

// hostAsSpelled strips the port of addr and keeps the host as written, as a
// PROXY header's source address arrives.
func hostAsSpelled(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

// TestAuthRateLimiterTier1CanonicalisesClientIP is the issue's reproduction:
// failures recorded under one spelling block the IP+username pair under every
// other spelling, and a success under another spelling clears them.
func TestAuthRateLimiterTier1CanonicalisesClientIP(t *testing.T) {
	ctx := context.Background()
	for _, tc := range equivalentClientSpellings {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultAuthRateLimiterConfig()
			cfg.Enabled = true
			cfg.MaxAttemptsPerIPUsername = 2
			cfg.MaxAttemptsPerIP = 0
			a := NewAuthRateLimiter("IMAP", "t", "h", cfg)
			defer a.Stop()

			first, second := &StringAddr{Addr: tc.a}, &StringAddr{Addr: tc.b}

			// A success under the other spelling clears a failure.
			a.RecordAuthAttempt(ctx, first, "user@example.com", false)
			a.RecordAuthAttempt(ctx, second, "user@example.com", true)
			a.RecordAuthAttempt(ctx, first, "user@example.com", false)
			if err := a.CanAttemptAuth(ctx, first, "user@example.com"); err != nil {
				t.Fatalf("a success from %q did not clear the failure from %q: %v", tc.b, tc.a, err)
			}

			a.RecordAuthAttempt(ctx, second, "user@example.com", false)
			for _, addr := range []*StringAddr{first, second} {
				if err := a.CanAttemptAuth(ctx, addr, "user@example.com"); !errors.Is(err, ErrRateLimitExceeded) {
					t.Errorf("CanAttemptAuth(%q) after one failure as %q and one as %q = %v, want rate limited",
						addr.Addr, tc.a, tc.b, err)
				}
			}
		})
	}
}

// TestAuthRateLimiterTier2CanonicalisesClientIP: Tier 2 counters and blocks,
// the TCP-level check and the PROXY-aware entry points use one key per client.
func TestAuthRateLimiterTier2CanonicalisesClientIP(t *testing.T) {
	ctx := context.Background()
	conn := &testAuthConn{localAddr: "203.0.113.1:143", remoteAddr: "203.0.113.2:40000"} // the front proxy
	for _, tc := range equivalentClientSpellings {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultAuthRateLimiterConfig()
			cfg.Enabled = true
			cfg.MaxAttemptsPerIPUsername = 0
			cfg.MaxAttemptsPerIP = 2
			a := NewAuthRateLimiter("IMAP", "t", "h", cfg)
			defer a.Stop()

			first, second := &StringAddr{Addr: tc.a}, &StringAddr{Addr: tc.b}
			viaProxy := &ProxyProtocolInfo{SrcIP: hostAsSpelled(tc.b)}

			a.RecordAuthAttempt(ctx, first, "anna@example.com", false)
			a.RecordAuthAttemptWithProxy(ctx, conn, viaProxy, "bob@example.com", false)

			if !a.IsIPBlocked(first) || !a.IsIPBlocked(second) {
				t.Errorf("IsIPBlocked(%q)=%v IsIPBlocked(%q)=%v after one failure under each spelling, want both blocked",
					tc.a, a.IsIPBlocked(first), tc.b, a.IsIPBlocked(second))
			}
			if !a.IsIPBlockedWithProxy(conn, viaProxy) {
				t.Errorf("IsIPBlockedWithProxy(SrcIP %q) = false, want blocked", viaProxy.SrcIP)
			}
			if err := a.CanAttemptAuth(ctx, second, "carol@example.com"); !errors.Is(err, ErrRateLimitExceeded) {
				t.Errorf("CanAttemptAuth(%q) = %v, want rate limited", tc.b, err)
			}
			if err := a.CanAttemptAuthWithProxy(ctx, conn, &ProxyProtocolInfo{SrcIP: hostAsSpelled(tc.a)}, "carol@example.com"); !errors.Is(err, ErrRateLimitExceeded) {
				t.Errorf("CanAttemptAuthWithProxy(SrcIP %q) = %v, want rate limited", hostAsSpelled(tc.a), err)
			}
			if got := len(a.GetBlockedEntries()); got != 1 {
				t.Errorf("one client is listed as %d blocked entries, want 1: %+v", got, a.GetBlockedEntries())
			}
		})
	}
}

// TestAuthRateLimiterDelayCanonicalisesClientIP: the progressive delay earned
// under one spelling applies under the others.
func TestAuthRateLimiterDelayCanonicalisesClientIP(t *testing.T) {
	ctx := context.Background()
	for _, tc := range equivalentClientSpellings {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultAuthRateLimiterConfig()
			cfg.Enabled = true
			cfg.MaxAttemptsPerIPUsername = 0
			cfg.MaxAttemptsPerIP = 100
			cfg.DelayStartThreshold = 2
			cfg.InitialDelay = time.Second
			cfg.MaxDelay = time.Minute
			a := NewAuthRateLimiter("IMAP", "t", "h", cfg)
			defer a.Stop()

			first, second := &StringAddr{Addr: tc.a}, &StringAddr{Addr: tc.b}
			a.RecordAuthAttempt(ctx, first, "anna@example.com", false)
			a.RecordAuthAttempt(ctx, second, "anna@example.com", false)
			for _, addr := range []*StringAddr{first, second} {
				if got := a.GetAuthenticationDelay(addr); got != time.Second {
					t.Errorf("GetAuthenticationDelay(%q) after two failures = %v, want 1s", addr.Addr, got)
				}
			}
		})
	}
}

// TestAuthDelaySlotsCanonicaliseClientIP: the cap on concurrent delays per IP
// counts one client once, whatever spelling each connection arrives with.
func TestAuthDelaySlotsCanonicaliseClientIP(t *testing.T) {
	dm := NewDelayManager(1)
	limiter := &MockAuthDelayHelper{delay: time.Hour}

	held, release := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = applyAuthenticationDelayWithManager(held, limiter, &StringAddr{Addr: "192.0.2.3:4000"}, "imap", dm)
	}()
	defer func() { release(); <-done }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		dm.mu.Lock()
		n := len(dm.ipCounts)
		dm.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first delay never took its slot")
		}
		time.Sleep(5 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := applyAuthenticationDelayWithManager(ctx, limiter, &StringAddr{Addr: "[::ffff:192.0.2.3]:5000"}, "imap", dm)
	if !errors.Is(err, ErrDelayQueueFull) {
		t.Errorf("second delay of one client under another spelling = %v, want ErrDelayQueueFull", err)
	}
}

// TestClusterRateLimitEventsCanonicaliseClientIP: a peer's BLOCK_IP,
// FAILURE_COUNT and UNBLOCK_IP apply to the client however the peer spelled it
// (a peer on a build before canonical keys broadcasts the address as given),
// and this node broadcasts the canonical key.
func TestClusterRateLimitEventsCanonicaliseClientIP(t *testing.T) {
	crl := newTestClusterRateLimiter(t) // MaxAttemptsPerIP: 10
	crl.syncBlocks = true
	crl.syncFailureCounts = true
	crl.limiter.config.DelayStartThreshold = 1
	crl.limiter.config.MaxDelay = time.Minute
	crl.limiter.SetClusterLimiter(crl)

	now := time.Now()
	deliverRateLimitEvent(t, crl, RateLimitEvent{
		Type:         RateLimitEventBlockIP,
		EventID:      "peer-block-mapped",
		IP:           "::ffff:192.0.2.60",
		Timestamp:    now,
		NodeID:       "node-b",
		Protocol:     crl.limiter.protocol,
		BlockedUntil: now.Add(time.Hour),
		FailureCount: 10,
		FirstFailure: now,
	})
	client := &StringAddr{Addr: "192.0.2.60:40000"}
	if !crl.limiter.IsIPBlocked(client) {
		t.Error("a peer's block of ::ffff:192.0.2.60 does not block 192.0.2.60")
	}
	if err := crl.limiter.CanAttemptAuth(context.Background(), client, "user@example.com"); !errors.Is(err, ErrRateLimitExceeded) {
		t.Errorf("CanAttemptAuth after a peer's block under another spelling = %v, want rate limited", err)
	}

	deliverRateLimitEvent(t, crl, RateLimitEvent{
		Type:      RateLimitEventUnblockIP,
		EventID:   "peer-unblock-mapped",
		IP:        "::FFFF:192.0.2.60",
		Timestamp: now.Add(time.Second),
		NodeID:    "node-b",
		Protocol:  crl.limiter.protocol,
	})
	if crl.limiter.IsIPBlocked(client) {
		t.Error("a peer's unblock of ::FFFF:192.0.2.60 does not lift the block of 192.0.2.60")
	}

	deliverRateLimitEvent(t, crl, RateLimitEvent{
		Type:         RateLimitEventFailureCount,
		EventID:      "peer-failure-count-v6",
		IP:           "2001:0DB8:0:0:0:0:0:7",
		Timestamp:    now,
		NodeID:       "node-b",
		Protocol:     crl.limiter.protocol,
		FailureCount: 9,
		LastDelay:    4 * time.Second,
		FirstFailure: now,
	})
	v6 := &StringAddr{Addr: "[2001:db8::7]:40000"}
	if got := crl.limiter.GetAuthenticationDelay(v6); got != 4*time.Second {
		t.Errorf("delay of 2001:db8::7 after a peer's 4s for 2001:0DB8:0:0:0:0:0:7 = %v, want 4s", got)
	}
	crl.limiter.RecordAuthAttempt(context.Background(), &StringAddr{Addr: "[2001:DB8::7]:40001"}, "", false)
	if !crl.limiter.IsIPBlocked(v6) {
		t.Error("a peer's 9 failures under one spelling plus a local one under another did not block the address")
	}

	// The block this node set is broadcast under the canonical key, so a peer
	// that sees the client as 2001:db8::7 holds it.
	var blockIP string
	for _, msg := range crl.GetBroadcasts(gossipPerMsgOverhead, gossipUDPLimit) {
		event, err := decodeRateLimitEvent(msg)
		if err != nil {
			t.Fatalf("decode broadcast: %v", err)
		}
		if event.Type == RateLimitEventBlockIP {
			blockIP = event.IP
		}
	}
	if blockIP != "2001:db8::7" {
		t.Errorf("broadcast BLOCK_IP carries %q, want the canonical 2001:db8::7", blockIP)
	}
}
