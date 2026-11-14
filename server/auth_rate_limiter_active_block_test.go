package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// requireBlocked fails the test unless CanAttemptAuth refuses addr/username with
// the given RateLimitError reason.
func requireBlocked(t *testing.T, limiter *AuthRateLimiter, addr net.Addr, username, reason string) {
	t.Helper()
	err := limiter.CanAttemptAuth(context.Background(), addr, username)
	var rle *RateLimitError
	if !errors.As(err, &rle) || rle.Reason != reason {
		t.Fatalf("CanAttemptAuth(%s, %s) = %v, want a %q refusal", addr, username, err, reason)
	}
}

// A success recorded for an address with an active Tier 2 block must not lift the
// block. Every caller checks CanAttemptAuth first, so such a success means the check
// was skipped (the proxies' lookup-cache shortcut) or a concurrent failure blocked the
// address while this login was being verified; either way the block stands until
// ip_block_duration ends. (#351)
func TestSuccessDoesNotLiftActiveIPBlock(t *testing.T) {
	cfg := AuthRateLimiterConfig{
		Enabled:          true,
		MaxAttemptsPerIP: 3,
		IPBlockDuration:  time.Hour,
		IPWindowDuration: time.Hour,
		CleanupInterval:  time.Hour,
	}
	blockedIP := "203.0.113.7"

	record := map[string]func(l *AuthRateLimiter, username string){
		"RecordAuthAttempt": func(l *AuthRateLimiter, username string) {
			l.RecordAuthAttempt(context.Background(), &StringAddr{Addr: blockedIP}, username, true)
		},
		"RecordAuthAttemptWithProxy": func(l *AuthRateLimiter, username string) {
			client, remote := net.Pipe()
			defer client.Close()
			defer remote.Close()
			l.RecordAuthAttemptWithProxy(context.Background(), client, &ProxyProtocolInfo{SrcIP: blockedIP}, username, true)
		},
	}

	for name, recordSuccess := range record {
		t.Run(name, func(t *testing.T) {
			limiter := NewAuthRateLimiter("test", "", "", cfg)
			defer limiter.Stop()
			addr := &StringAddr{Addr: blockedIP}

			for i := 0; i < cfg.MaxAttemptsPerIP; i++ {
				limiter.RecordAuthAttempt(context.Background(), addr, fmt.Sprintf("guess%d@example.com", i), false)
			}
			requireBlocked(t, limiter, addr, "user@example.com", "ip_blocked")

			recordSuccess(limiter, "user@example.com")

			requireBlocked(t, limiter, addr, "user@example.com", "ip_blocked")
			if !limiter.IsIPBlocked(addr) {
				t.Error("IsIPBlocked = false after a success from the blocked address")
			}
		})
	}
}

// Same rule for Tier 1: a success for an IP+username pair with an active block leaves
// the block in place. (#351)
func TestSuccessDoesNotLiftActiveIPUsernameBlock(t *testing.T) {
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 2,
		IPUsernameBlockDuration:  time.Hour,
		IPUsernameWindowDuration: time.Hour,
		CleanupInterval:          time.Hour,
	})
	defer limiter.Stop()
	ctx := context.Background()
	addr := &StringAddr{Addr: "203.0.113.8"}

	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	requireBlocked(t, limiter, addr, "user@example.com", "ip_username_blocked")

	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", true)

	requireBlocked(t, limiter, addr, "user@example.com", "ip_username_blocked")
}

// A success for an address that is NOT blocked still clears its counters, so a user
// who mistyped a password a few times starts from zero after logging in.
func TestSuccessClearsCountersOfUnblockedAddress(t *testing.T) {
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 5,
		IPUsernameBlockDuration:  time.Hour,
		IPUsernameWindowDuration: time.Hour,
		MaxAttemptsPerIP:         5,
		IPBlockDuration:          time.Hour,
		IPWindowDuration:         time.Hour,
		CleanupInterval:          time.Hour,
	})
	defer limiter.Stop()
	ctx := context.Background()
	addr := &StringAddr{Addr: "203.0.113.9"}

	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
	limiter.RecordAuthAttempt(ctx, addr, "user@example.com", true)

	limiter.ipMu.RLock()
	_, ipTracked := limiter.ipFailureCounts["203.0.113.9"]
	limiter.ipMu.RUnlock()
	limiter.ipUsernameMu.RLock()
	_, pairTracked := limiter.blockedIPUsernames["203.0.113.9|user@example.com"]
	limiter.ipUsernameMu.RUnlock()
	if ipTracked || pairTracked {
		t.Errorf("success left counters behind: ip=%v ip+username=%v", ipTracked, pairTracked)
	}
}

// When max_ip_entries is reached, eviction must make room from the addresses that are
// not blocked. Picking the oldest first failure regardless deleted the block of the
// address that had been failing longest, ending it before ip_block_duration. (#351)
func TestIPSizeLimitKeepsActiveBlocks(t *testing.T) {
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:          true,
		MaxAttemptsPerIP: 2,
		IPBlockDuration:  time.Hour,
		IPWindowDuration: time.Hour,
		CleanupInterval:  time.Hour,
		MaxIPEntries:     3,
	})
	defer limiter.Stop()
	ctx := context.Background()
	fail := func(ip string) {
		limiter.RecordAuthAttempt(ctx, &StringAddr{Addr: ip}, "user@example.com", false)
		time.Sleep(2 * time.Millisecond) // distinct FirstFailure times
	}

	// The attacker fails first, so its entry has the oldest first failure.
	attacker := &StringAddr{Addr: "198.51.100.1"}
	fail(attacker.Addr)
	fail(attacker.Addr)
	requireBlocked(t, limiter, attacker, "user@example.com", "ip_blocked")

	// Failures from many other addresses keep the table at its limit.
	for i := 1; i <= 10; i++ {
		fail(fmt.Sprintf("192.0.2.%d", i))
	}

	requireBlocked(t, limiter, attacker, "user@example.com", "ip_blocked")

	limiter.ipMu.RLock()
	defer limiter.ipMu.RUnlock()
	if n := len(limiter.ipFailureCounts); n > 3 {
		t.Errorf("ipFailureCounts has %d entries, want at most max_ip_entries (3)", n)
	}
	if _, ok := limiter.ipFailureCounts["192.0.2.10"]; !ok {
		t.Error("the newest address is not tracked")
	}
	if _, ok := limiter.ipFailureCounts["192.0.2.1"]; ok {
		t.Error("the oldest unblocked address was not the one evicted")
	}
}

// When every tracked address is blocked, eviction still keeps the table bounded by
// dropping the oldest failure counter, but the block itself stays and is enforced.
func TestIPSizeLimitAllBlockedKeepsBlocks(t *testing.T) {
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:          true,
		MaxAttemptsPerIP: 1,
		IPBlockDuration:  time.Hour,
		IPWindowDuration: time.Hour,
		CleanupInterval:  time.Hour,
		MaxIPEntries:     2,
	})
	defer limiter.Stop()
	ctx := context.Background()

	ips := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
	for _, ip := range ips {
		limiter.RecordAuthAttempt(ctx, &StringAddr{Addr: ip}, "user@example.com", false)
		time.Sleep(2 * time.Millisecond)
	}

	for _, ip := range ips {
		requireBlocked(t, limiter, &StringAddr{Addr: ip}, "user@example.com", "ip_blocked")
	}
	limiter.ipMu.RLock()
	defer limiter.ipMu.RUnlock()
	if n := len(limiter.ipFailureCounts); n != 2 {
		t.Errorf("ipFailureCounts has %d entries, want max_ip_entries (2)", n)
	}
	if _, ok := limiter.ipFailureCounts["198.51.100.1"]; ok {
		t.Error("the oldest counter was not the one evicted")
	}
}

func TestFullAuthTablesStillAccumulateFailures(t *testing.T) {
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIP:         2,
		MaxAttemptsPerIPUsername: 2,
		IPBlockDuration:          time.Hour,
		IPUsernameBlockDuration:  time.Hour,
		IPWindowDuration:         time.Hour,
		CleanupInterval:          time.Hour,
		MaxIPEntries:             1,
		MaxIPUsernameEntries:     1,
		MaxUsernameEntries:       1,
	})
	defer limiter.Stop()
	ctx := context.Background()
	addr := &StringAddr{Addr: "198.51.100.1"}
	const username = "user@example.com"
	for range 2 {
		limiter.RecordAuthAttempt(ctx, addr, username, false)
	}
	limiter.ipMu.RLock()
	ipFailures := limiter.ipFailureCounts[addr.Addr].FailureCount
	limiter.ipMu.RUnlock()
	limiter.ipUsernameMu.RLock()
	pairFailures := limiter.blockedIPUsernames[addr.Addr+"|"+username].FailureCount
	limiter.ipUsernameMu.RUnlock()
	if ipFailures != 2 || pairFailures != 2 || limiter.getUsernameFailureCount(username) != 2 {
		t.Errorf("updating a full table reset existing counters: IP=%d pair=%d username=%d, want 2 each", ipFailures, pairFailures, limiter.getUsernameFailureCount(username))
	}
	if err := limiter.CanAttemptAuth(ctx, addr, username); err == nil {
		t.Error("repeated failures at table capacity never reached the block threshold")
	}
}
