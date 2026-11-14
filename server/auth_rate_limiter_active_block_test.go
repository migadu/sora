package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
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
	_, pairTracked := limiter.ipUsernameFailureCounts["203.0.113.9|user@example.com"]
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

// An IP+username block lasts until ip_username_block_duration ends. The periodic
// cleanup aged entries out by ip_username_window_duration alone, so a blocked pair,
// whose last failure is the one that blocked it, lost its block as soon as the window
// had passed: with the defaults (window 10m, block 15m) after 10 to 15 minutes.
// Failure counters still age out by the window. (#513)
func TestIPUsernameBlockOutlastsWindowCleanup(t *testing.T) {
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 2,
		IPUsernameBlockDuration:  time.Hour,
		IPUsernameWindowDuration: 50 * time.Millisecond,
		CleanupInterval:          time.Hour,
	})
	defer limiter.Stop()
	ctx := context.Background()
	blocked := &StringAddr{Addr: "203.0.113.20"}
	counted := &StringAddr{Addr: "203.0.113.21"}

	limiter.RecordAuthAttempt(ctx, blocked, "user@example.com", false)
	limiter.RecordAuthAttempt(ctx, blocked, "user@example.com", false)
	limiter.RecordAuthAttempt(ctx, counted, "user@example.com", false)
	requireBlocked(t, limiter, blocked, "user@example.com", "ip_username_blocked")

	time.Sleep(100 * time.Millisecond) // past the window, well within the block
	limiter.cleanupExpiredEntries()

	requireBlocked(t, limiter, blocked, "user@example.com", "ip_username_blocked")

	// The counter of the unblocked pair aged out: one more failure is its first.
	limiter.RecordAuthAttempt(ctx, counted, "user@example.com", false)
	if err := limiter.CanAttemptAuth(ctx, counted, "user@example.com"); err != nil {
		t.Errorf("a failure counter older than the window survived cleanup: %v", err)
	}
}

// Failures from other pairs that fill max_ip_username_entries make room by dropping
// failure counters, never an active block. Eviction by oldest first failure removed the
// block of the pair that had been failing longest. (#513)
func TestIPUsernameSizeLimitKeepsActiveBlocks(t *testing.T) {
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 2,
		IPUsernameBlockDuration:  time.Hour,
		IPUsernameWindowDuration: time.Hour,
		CleanupInterval:          time.Hour,
		MaxIPUsernameEntries:     3,
	})
	defer limiter.Stop()
	ctx := context.Background()
	fail := func(addr *StringAddr, username string) {
		limiter.RecordAuthAttempt(ctx, addr, username, false)
		time.Sleep(2 * time.Millisecond) // distinct FirstFailure times
	}

	// The attacker fails first, so its entry has the oldest first failure.
	attacker := &StringAddr{Addr: "198.51.100.1"}
	fail(attacker, "user@example.com")
	fail(attacker, "user@example.com")
	requireBlocked(t, limiter, attacker, "user@example.com", "ip_username_blocked")

	// Single failures of other pairs keep the table at its limit.
	for i := 1; i <= 10; i++ {
		fail(&StringAddr{Addr: "192.0.2.1"}, fmt.Sprintf("user%d@example.com", i))
	}

	requireBlocked(t, limiter, attacker, "user@example.com", "ip_username_blocked")

	// The newest pair is still counted: its second failure blocks it.
	newest := &StringAddr{Addr: "192.0.2.1"}
	fail(newest, "user10@example.com")
	requireBlocked(t, limiter, newest, "user10@example.com", "ip_username_blocked")
}

// The reproduction of #521: with max_attempts_per_ip_username = 1 every failure blocks
// its pair, and the pair that brought the table over max_ip_username_entries evicted the
// oldest block. Blocks are bounded by max_ip_username_entries in a table of their own; a
// block is never dropped while it is active, so once that table is full of active blocks
// a further pair is not blocked (Tier 2 still counts its address) until one expires.
func TestIPUsernameBlockTableFullKeepsActiveBlocks(t *testing.T) {
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 1,
		IPUsernameBlockDuration:  time.Hour,
		IPUsernameWindowDuration: time.Hour,
		CleanupInterval:          time.Hour,
		MaxIPUsernameEntries:     2,
	})
	defer limiter.Stop()
	ctx := context.Background()

	addrs := []*StringAddr{{Addr: "198.51.100.1"}, {Addr: "198.51.100.2"}, {Addr: "198.51.100.3"}}
	for _, addr := range addrs {
		limiter.RecordAuthAttempt(ctx, addr, "user@example.com", false)
		time.Sleep(2 * time.Millisecond)
	}

	requireBlocked(t, limiter, addrs[0], "user@example.com", "ip_username_blocked")
	requireBlocked(t, limiter, addrs[1], "user@example.com", "ip_username_blocked")
	if n := len(limiter.GetBlockedEntries()); n != 2 {
		t.Errorf("%d active IP+username blocks, want max_ip_username_entries (2)", n)
	}
}

// A full block table makes room from blocks that have expired but not been cleaned up
// yet, so a new block is stored rather than refused.
func TestIPUsernameBlockTableReusesExpiredBlocks(t *testing.T) {
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 1,
		IPUsernameBlockDuration:  50 * time.Millisecond,
		IPUsernameWindowDuration: time.Hour,
		CleanupInterval:          time.Hour,
		MaxIPUsernameEntries:     1,
	})
	defer limiter.Stop()
	ctx := context.Background()
	first := &StringAddr{Addr: "198.51.100.1"}
	second := &StringAddr{Addr: "198.51.100.2"}

	limiter.RecordAuthAttempt(ctx, first, "user@example.com", false)
	requireBlocked(t, limiter, first, "user@example.com", "ip_username_blocked")
	time.Sleep(100 * time.Millisecond) // the first block expires

	limiter.RecordAuthAttempt(ctx, second, "user@example.com", false)
	requireBlocked(t, limiter, second, "user@example.com", "ip_username_blocked")
	if err := limiter.CanAttemptAuth(ctx, first, "user@example.com"); err != nil {
		t.Errorf("expired block still enforced: %v", err)
	}
}

// A failure's time is taken before the Tier 1 lock, so a failure can be stored after a
// later one. Recorded while its pair is blocked, it must not end the block earlier than
// the later failure did.
func TestIPUsernameBlockRenewalNeverShortensBlock(t *testing.T) {
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 1,
		IPUsernameBlockDuration:  time.Minute,
		IPUsernameWindowDuration: time.Hour,
		CleanupInterval:          time.Hour,
	})
	defer limiter.Stop()
	const key = "198.51.100.1|user@example.com"
	t0 := time.Now()

	limiter.updateIPUsernameFailure("198.51.100.1", "user@example.com", t0.Add(20*time.Second))
	limiter.updateIPUsernameFailure("198.51.100.1", "user@example.com", t0.Add(10*time.Second))

	limiter.ipUsernameMu.RLock()
	defer limiter.ipUsernameMu.RUnlock()
	blocked, ok := limiter.blockedIPUsernames[key]
	if !ok {
		t.Fatal("pair not blocked")
	}
	if want := t0.Add(80 * time.Second); blocked.BlockedUntil.Before(want) {
		t.Errorf("block ends %v after t0, want %v: an earlier failure shortened it",
			blocked.BlockedUntil.Sub(t0), want.Sub(t0))
	}
	if blocked.FailureCount != 2 {
		t.Errorf("failure count %d, want 2", blocked.FailureCount)
	}
}

// A full block table is searched for a block that has ended only once the earliest one
// can have ended. A block stored with an earlier end than those already there (its
// failure time was taken first) moves that point, so its slot is reused once it ends.
func TestIPUsernameFullBlockTableReusesOutOfOrderBlock(t *testing.T) {
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 1,
		IPUsernameBlockDuration:  time.Minute,
		IPUsernameWindowDuration: time.Hour,
		CleanupInterval:          time.Hour,
		MaxIPUsernameEntries:     2,
	})
	defer limiter.Stop()
	t0 := time.Now()
	fail := func(ip string, at time.Duration) {
		limiter.updateIPUsernameFailure(ip, "user@example.com", t0.Add(at))
	}
	isBlocked := func(ip string) bool {
		limiter.ipUsernameMu.RLock()
		defer limiter.ipUsernameMu.RUnlock()
		_, ok := limiter.blockedIPUsernames[ip+"|user@example.com"]
		return ok
	}

	fail("198.51.100.1", 20*time.Second) // blocked until t0+80s
	fail("198.51.100.2", 30*time.Second) // blocked until t0+90s: the table is full
	fail("198.51.100.3", 40*time.Second) // no block has ended: not blocked
	if isBlocked("198.51.100.3") {
		t.Fatal("a block was stored in a table full of active blocks")
	}

	// .1's block is gone (as when CanAttemptAuth removes it), and a failure taken
	// before the others is stored in its slot.
	limiter.ipUsernameMu.Lock()
	delete(limiter.blockedIPUsernames, "198.51.100.1|user@example.com")
	limiter.ipUsernameMu.Unlock()
	fail("198.51.100.4", 10*time.Second) // blocked until t0+70s

	fail("198.51.100.5", 75*time.Second) // .4's block has ended: .5 takes its slot
	if !isBlocked("198.51.100.5") {
		t.Error("a block that had ended kept its slot in a full table")
	}
}

// CanAttemptAuth removes a block that has ended after trading its read lock for the
// write lock. A failure that blocks the address (or pair) anew in between must survive
// that removal. The window is short, so the race is retried many times.
func TestExpiredBlockRemovalKeepsNewBlock(t *testing.T) {
	prev := logger.Swap(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { logger.Swap(prev) })
	const (
		ip       = "203.0.113.7"
		username = "user@example.com"
		key      = ip + "|" + username
		rounds   = 30000
	)
	ctx := context.Background()
	addr := &StringAddr{Addr: ip}

	race := func(t *testing.T, limiter *AuthRateLimiter, reset func(), fail func(), reason string) {
		for i := 0; i < rounds; i++ {
			reset()
			var wg sync.WaitGroup
			start := make(chan struct{})
			wg.Add(2)
			go func() { defer wg.Done(); <-start; _ = limiter.CanAttemptAuth(ctx, addr, username) }()
			go func() { defer wg.Done(); <-start; fail() }()
			close(start)
			wg.Wait()
			var rlErr *RateLimitError
			if err := limiter.CanAttemptAuth(ctx, addr, username); !errors.As(err, &rlErr) || rlErr.Reason != reason {
				t.Fatalf("round %d: the block set by the last failure was removed (CanAttemptAuth = %v)", i, err)
			}
		}
	}

	t.Run("ip", func(t *testing.T) {
		limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
			Enabled:             true,
			MaxAttemptsPerIP:    3,
			IPBlockDuration:     time.Hour,
			IPWindowDuration:    time.Hour,
			CleanupInterval:     time.Hour,
			DelayStartThreshold: 100,
		})
		defer limiter.Stop()
		race(t, limiter, func() {
			limiter.ipMu.Lock()
			defer limiter.ipMu.Unlock()
			limiter.blockedIPs[ip] = &BlockedIPInfo{BlockedUntil: time.Now().Add(-time.Second)}
			limiter.ipFailureCounts[ip] = &IPFailureInfo{FailureCount: 2, FirstFailure: time.Now()}
		}, func() { limiter.updateFailureTracking(ip, time.Now()) }, "ip_blocked")
	})

	t.Run("ip_username", func(t *testing.T) {
		limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
			Enabled:                  true,
			MaxAttemptsPerIPUsername: 1,
			IPUsernameBlockDuration:  time.Hour,
			IPUsernameWindowDuration: time.Hour,
			CleanupInterval:          time.Hour,
		})
		defer limiter.Stop()
		race(t, limiter, func() {
			limiter.ipUsernameMu.Lock()
			defer limiter.ipUsernameMu.Unlock()
			limiter.blockedIPUsernames[key] = &BlockedIPUsernameInfo{BlockedUntil: time.Now().Add(-time.Second)}
		}, func() { limiter.updateIPUsernameFailure(ip, username, time.Now()) }, "ip_username_blocked")
	})
}

// Failed logins of a pair that has reached its threshold while the block table is full
// of active blocks: each one must not search the whole table.
func BenchmarkIPUsernameFailureAtFullBlockTable(b *testing.B) {
	const entries = 100000
	prev := logger.Swap(slog.New(slog.NewTextHandler(io.Discard, nil)))
	b.Cleanup(func() { logger.Swap(prev) })
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 1,
		IPUsernameBlockDuration:  time.Hour,
		IPUsernameWindowDuration: time.Hour,
		CleanupInterval:          time.Hour,
		MaxIPUsernameEntries:     entries,
	})
	defer limiter.Stop()
	t0 := time.Now()
	for i := 0; i < entries; i++ {
		limiter.updateIPUsernameFailure("198.51.100.1", fmt.Sprintf("user%d@example.com", i), t0)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		limiter.updateIPUsernameFailure("203.0.113.1", "user@example.com", t0)
	}
}

// Concurrent failures, successes, checks and cleanups on a few pairs at the size limit,
// for the race detector; afterwards the Tier 1 tables are still within their bounds.
func TestIPUsernameTablesConcurrentUse(t *testing.T) {
	const limit = 4
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 2,
		IPUsernameBlockDuration:  time.Millisecond,
		IPUsernameWindowDuration: time.Millisecond,
		CleanupInterval:          time.Hour,
		MaxIPUsernameEntries:     limit,
	})
	defer limiter.Stop()
	ctx := context.Background()

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				addr := &StringAddr{Addr: fmt.Sprintf("198.51.100.%d", (g+i)%6)}
				username := fmt.Sprintf("user%d@example.com", i%3)
				switch i % 7 {
				case 0:
					limiter.RecordAuthAttempt(ctx, addr, username, true)
				case 1:
					if g == 0 { // a single cleaner, like the cleanup goroutine
						limiter.cleanupExpiredEntries()
					}
				case 2:
					limiter.GetBlockedEntries()
				default:
					_ = limiter.CanAttemptAuth(ctx, addr, username)
					limiter.RecordAuthAttempt(ctx, addr, username, false)
				}
			}
		}(g)
	}
	wg.Wait()

	limiter.ipUsernameMu.RLock()
	defer limiter.ipUsernameMu.RUnlock()
	if c, b := len(limiter.ipUsernameFailureCounts), len(limiter.blockedIPUsernames); c > limit || b > limit {
		t.Errorf("%d IP+username counters and %d blocks, want at most %d of each", c, b, limit)
	}
}

// Out-of-order failures must preserve an IP-wide block just as they do for a pair.
func TestIPBlockRenewalNeverShortensBlock(t *testing.T) {
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled: true, MaxAttemptsPerIP: 1, IPBlockDuration: time.Minute,
		IPWindowDuration: time.Hour, CleanupInterval: time.Hour, DelayStartThreshold: 100,
	})
	defer limiter.Stop()
	t0 := time.Now()
	limiter.updateFailureTracking("198.51.100.1", t0.Add(20*time.Second))
	limiter.updateFailureTracking("198.51.100.1", t0.Add(10*time.Second))
	limiter.ipMu.RLock()
	defer limiter.ipMu.RUnlock()
	blocked := limiter.blockedIPs["198.51.100.1"]
	if want := t0.Add(80 * time.Second); blocked.BlockedUntil.Before(want) {
		t.Fatalf("block ends %v after t0, want %v", blocked.BlockedUntil.Sub(t0), want.Sub(t0))
	}
	if !blocked.LastFailure.Equal(t0.Add(20 * time.Second)) {
		t.Errorf("last failure = %v, want latest captured failure", blocked.LastFailure)
	}
	if blocked.FailureCount != 2 {
		t.Errorf("failure count = %d, want 2", blocked.FailureCount)
	}
}
