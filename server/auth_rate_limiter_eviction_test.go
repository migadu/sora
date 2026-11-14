package server

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"math/rand/v2"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/logger"
)

// discardAuthLimiterLogs drops log output for the rest of the test: blocks and full
// tables log on every failure.
func discardAuthLimiterLogs(tb testing.TB) {
	tb.Helper()
	prev := logger.Swap(slog.New(slog.NewTextHandler(io.Discard, nil)))
	tb.Cleanup(func() { logger.Swap(prev) })
}

// requireKeys fails t unless table holds exactly the keys want.
func requireKeys[V any](t *testing.T, mu *sync.RWMutex, table map[string]V, want ...string) {
	t.Helper()
	mu.RLock()
	got := slices.Sorted(maps.Keys(table))
	mu.RUnlock()
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("tracked %v, want %v", got, want)
	}
}

// trackingTable is one of the limiter's bounded failure counter tables.
type trackingTable struct {
	name string
	key  func(i int) string                                 // the i-th distinct key
	fail func(l *AuthRateLimiter, key string, at time.Time) // records a failure for key
}

var trackingTables = []trackingTable{
	{
		name: "ip_username",
		key:  func(i int) string { return fmt.Sprintf("user%d@example.com", i) },
		fail: func(l *AuthRateLimiter, username string, at time.Time) {
			l.updateIPUsernameFailure("192.0.2.1", username, at)
		},
	},
	{
		name: "ip",
		key:  func(i int) string { return fmt.Sprintf("2001:db8::%x:%x", i>>16, i&0xffff) },
		fail: func(l *AuthRateLimiter, ip string, at time.Time) { l.updateFailureTracking(ip, at) },
	},
	{
		name: "username",
		key:  func(i int) string { return fmt.Sprintf("user%d@example.com", i) },
		fail: func(l *AuthRateLimiter, username string, at time.Time) { l.updateUsernameFailure(username, at) },
	},
}

// newEvictionTestLimiter returns a limiter whose tables each hold at most entries
// counters, with thresholds that the failures of these tests do not reach.
func newEvictionTestLimiter(tb testing.TB, entries int) *AuthRateLimiter {
	tb.Helper()
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                  true,
		MaxAttemptsPerIPUsername: 1000,
		IPUsernameBlockDuration:  time.Hour,
		IPUsernameWindowDuration: time.Hour,
		MaxAttemptsPerIP:         1000,
		IPBlockDuration:          time.Hour,
		IPWindowDuration:         time.Hour,
		UsernameWindowDuration:   time.Hour,
		DelayStartThreshold:      1000,
		CleanupInterval:          time.Hour,
		MaxIPUsernameEntries:     entries,
		MaxIPEntries:             entries,
		MaxUsernameEntries:       entries,
	})
	tb.Cleanup(limiter.Stop)
	return limiter
}

// failureCostAtCapacity returns the best per-failure time over a few rounds of failures
// with new keys into table, filled to its limit of entries, so that each one has to make
// room first. The minimum smooths out GC and scheduling noise.
func failureCostAtCapacity(t *testing.T, table trackingTable, entries int) time.Duration {
	limiter := newEvictionTestLimiter(t, entries)
	t0 := time.Now()
	for i := range entries {
		table.fail(limiter, table.key(i), t0.Add(time.Duration(i)))
	}
	const rounds, perRound = 5, 100
	keys := make([]string, rounds*perRound)
	for i := range keys {
		keys[i] = table.key(entries + i)
	}
	best := time.Duration(math.MaxInt64)
	for r := range rounds {
		at := time.Now()
		start := time.Now()
		for _, key := range keys[r*perRound : (r+1)*perRound] {
			table.fail(limiter, key, at)
		}
		if d := time.Since(start) / perRound; d < best {
			best = d
		}
	}
	return best
}

// A failed login that adds a key to a full table makes room while it holds the table's
// write lock, which CanAttemptAuth on every connection of the protocol waits for. Its
// cost must not grow with the table's limit. (#719)
func TestAuthLimiterFailureAtCapacityCostIndependentOfSize(t *testing.T) {
	if testing.Short() {
		t.Skip("timing test")
	}
	discardAuthLimiterLogs(t)
	for _, table := range trackingTables {
		t.Run(table.name, func(t *testing.T) {
			small := failureCostAtCapacity(t, table, 1_000)
			large := failureCostAtCapacity(t, table, 100_000)
			t.Logf("failure with a new key into a full table: 1000 entries = %v, 100000 entries = %v", small, large)
			// Searching all entries makes the large table ~100x slower; a queue leaves
			// the logarithm and the cache misses of the bigger table.
			if large > 20*small {
				t.Errorf("a failure with a new key costs %v at 100000 entries vs %v at 1000: making room scales with the table", large, small)
			}
		})
	}
}

// A peer's failure count can carry an earlier first failure than this node saw, for an
// address it tracks or one it adds: the eviction order follows it.
func TestIPEvictionFollowsPeerFirstFailure(t *testing.T) {
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:             true,
		MaxAttemptsPerIP:    100,
		IPBlockDuration:     time.Hour,
		IPWindowDuration:    time.Hour,
		DelayStartThreshold: 100,
		CleanupInterval:     time.Hour,
		MaxIPEntries:        3,
	})
	defer limiter.Stop()
	crl := &ClusterRateLimiter{limiter: limiter, syncFailureCounts: true}
	t0 := time.Now()
	for i, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		limiter.updateFailureTracking(ip, t0.Add(time.Duration(i+1)*time.Second))
	}

	// .3 failed last here, but a peer saw it fail before the others.
	crl.handleFailureCount(RateLimitEvent{IP: "192.0.2.3", FailureCount: 1, FirstFailure: t0, Timestamp: t0})
	limiter.updateFailureTracking("192.0.2.4", t0.Add(4*time.Second))
	requireKeys(t, &limiter.ipMu, limiter.ipFailureCounts, "192.0.2.1", "192.0.2.2", "192.0.2.4")

	// A peer adds an address that failed an hour ago: it makes room like a local
	// failure, and is the next to go.
	crl.handleFailureCount(RateLimitEvent{IP: "192.0.2.5", FailureCount: 1, FirstFailure: t0.Add(-time.Hour), Timestamp: t0})
	requireKeys(t, &limiter.ipMu, limiter.ipFailureCounts, "192.0.2.2", "192.0.2.4", "192.0.2.5")
	limiter.updateFailureTracking("192.0.2.6", t0.Add(6*time.Second))
	requireKeys(t, &limiter.ipMu, limiter.ipFailureCounts, "192.0.2.2", "192.0.2.4", "192.0.2.6")
}

// A peer's username failure is counted from its own time, which can be earlier than
// the failures this node recorded before it arrived.
func TestUsernameEvictionFollowsPeerTimestamps(t *testing.T) {
	limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
		Enabled:                true,
		UsernameWindowDuration: time.Hour,
		CleanupInterval:        time.Hour,
		MaxUsernameEntries:     3,
	})
	defer limiter.Stop()
	crl := &ClusterRateLimiter{limiter: limiter}
	t0 := time.Now()
	for i := 1; i <= 3; i++ {
		limiter.updateUsernameFailure(fmt.Sprintf("user%d@example.com", i), t0.Add(time.Duration(i)*time.Second))
	}

	crl.handleUsernameFailure(RateLimitEvent{Username: "user4@example.com", Timestamp: t0})
	requireKeys(t, &limiter.usernameMu, limiter.usernameFailureCounts, "user2@example.com", "user3@example.com", "user4@example.com")
	limiter.updateUsernameFailure("user5@example.com", t0.Add(5*time.Second))
	requireKeys(t, &limiter.usernameMu, limiter.usernameFailureCounts, "user2@example.com", "user3@example.com", "user5@example.com")
}

// The counter of a blocked address is passed over while its block runs, also after a
// peer extends the block, and goes in its turn once the block has ended. (#351)
func TestIPEvictionPassesOverBlockedAddressUntilBlockEnds(t *testing.T) {
	const block = 250 * time.Millisecond
	// .1 fails first and is blocked; .2 and .3 fill the table; .4 makes room by
	// dropping .2, the oldest address without a block.
	setup := func(t *testing.T) (*AuthRateLimiter, *ClusterRateLimiter) {
		limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
			Enabled:             true,
			MaxAttemptsPerIP:    2,
			IPBlockDuration:     block,
			IPWindowDuration:    time.Hour,
			DelayStartThreshold: 100,
			CleanupInterval:     time.Hour,
			MaxIPEntries:        3,
		})
		t.Cleanup(limiter.Stop)
		t0 := time.Now()
		limiter.updateFailureTracking("192.0.2.1", t0)
		limiter.updateFailureTracking("192.0.2.1", t0)
		limiter.updateFailureTracking("192.0.2.2", t0.Add(time.Millisecond))
		limiter.updateFailureTracking("192.0.2.3", t0.Add(2*time.Millisecond))
		limiter.updateFailureTracking("192.0.2.4", t0.Add(3*time.Millisecond))
		requireKeys(t, &limiter.ipMu, limiter.ipFailureCounts, "192.0.2.1", "192.0.2.3", "192.0.2.4")
		return limiter, &ClusterRateLimiter{limiter: limiter, syncBlocks: true}
	}

	t.Run("block ends", func(t *testing.T) {
		limiter, _ := setup(t)
		time.Sleep(block + 50*time.Millisecond)
		limiter.updateFailureTracking("192.0.2.5", time.Now())
		requireKeys(t, &limiter.ipMu, limiter.ipFailureCounts, "192.0.2.3", "192.0.2.4", "192.0.2.5")
	})

	t.Run("block extended by a peer", func(t *testing.T) {
		limiter, crl := setup(t)
		now := time.Now()
		crl.handleBlockIP(RateLimitEvent{IP: "192.0.2.1", BlockedUntil: now.Add(time.Hour), FailureCount: 2, FirstFailure: now, Timestamp: now})
		time.Sleep(block + 50*time.Millisecond) // past the end of the local block
		limiter.updateFailureTracking("192.0.2.5", time.Now())
		requireKeys(t, &limiter.ipMu, limiter.ipFailureCounts, "192.0.2.1", "192.0.2.4", "192.0.2.5")
	})
}

// counterTimes are the first and last failure of a counter.
type counterTimes struct{ first, last time.Time }

// checkEviction fails t unless operation op removed no counter from table besides own's,
// or, when it added own to the full table, removed exactly one: a counter with the
// oldest first failure among those not passed over. blocked holds the addresses with an
// active block, which the IP table passes over while it has any other counter (nil for
// the other tables); when every counter is passed over, any one may go.
func checkEviction(t *testing.T, op int, table string, capacity int, before, after map[string]counterTimes, own string, blocked map[string]bool) {
	t.Helper()
	var dropped []string
	for key := range before {
		if _, kept := after[key]; !kept && key != own {
			dropped = append(dropped, key)
		}
	}
	_, had := before[own]
	_, has := after[own]
	if own == "" || had || !has || len(before) < capacity {
		if len(dropped) > 0 {
			t.Fatalf("op %d: %s table dropped %v without having to make room for %q", op, table, dropped, own)
		}
		return
	}
	if len(dropped) != 1 {
		t.Fatalf("op %d: adding %q to the full %s table dropped %v, want one counter", op, table, own, dropped)
	}
	victim := dropped[0]
	if !slices.ContainsFunc(slices.Collect(maps.Keys(before)), func(key string) bool { return !blocked[key] }) {
		return
	}
	if blocked[victim] {
		t.Fatalf("op %d: %s table dropped %q, which has an active block, while others had none", op, table, victim)
	}
	for key, c := range before {
		if !blocked[key] && c.first.Before(before[victim].first) {
			t.Fatalf("op %d: %s table dropped %q (first failure %v) while %q failed first (%v)",
				op, table, victim, before[victim].first, key, c.first)
		}
	}
}

// checkCleanup fails t unless cleanup op left exactly the counters of table whose last
// failure is not before cutoff.
func checkCleanup(t *testing.T, op int, table string, before, after map[string]counterTimes, cutoff time.Time) {
	t.Helper()
	for key, c := range before {
		_, kept := after[key]
		if want := !c.last.Before(cutoff); kept != want {
			t.Fatalf("op %d: cleanup of the %s table kept %q (last failure %v) = %v, want %v", op, table, key, c.last, kept, want)
		}
	}
	if len(after) > len(before) {
		t.Fatalf("op %d: cleanup added counters to the %s table", op, table)
	}
}

// Random failures, successes, peer events, checks and cleanups on small full tables: each
// counter dropped to make room is one that a search of the whole table would pick.
func TestAuthLimiterEvictionVictimsUnderRandomOperations(t *testing.T) {
	discardAuthLimiterLogs(t)
	const (
		capacity = 6
		pool     = 12 // distinct addresses and usernames
		// Blocks do not end while the test runs, so every address ends up blocked
		// after a while: a fresh limiter for every round keeps the mix.
		rounds, ops = 50, 400
		// Failures are whole minutes before base and durations end half a minute past
		// one, so no block or window ends while the test runs.
		grid = time.Minute
		span = time.Hour + grid/2
	)
	ctx := context.Background()
	rng := rand.New(rand.NewPCG(719, 1))
	base := time.Now()
	at := func() time.Time { return base.Add(-time.Duration(rng.IntN(120)) * grid) }
	ip := func() string { return fmt.Sprintf("192.0.2.%d", rng.IntN(pool)+1) }
	user := func() string { return fmt.Sprintf("user%d@example.com", rng.IntN(pool)) }

	for round := range rounds {
		limiter := NewAuthRateLimiter("test", "", "", AuthRateLimiterConfig{
			Enabled:                  true,
			MaxAttemptsPerIPUsername: 3,
			IPUsernameBlockDuration:  span,
			IPUsernameWindowDuration: span,
			MaxAttemptsPerIP:         3,
			IPBlockDuration:          span,
			IPWindowDuration:         span,
			UsernameWindowDuration:   span,
			DelayStartThreshold:      2,
			InitialDelay:             time.Second,
			MaxDelay:                 time.Minute,
			DelayMultiplier:          2,
			CleanupInterval:          time.Hour,
			MaxIPUsernameEntries:     capacity,
			MaxIPEntries:             capacity,
			MaxUsernameEntries:       capacity,
		})
		crl := &ClusterRateLimiter{limiter: limiter, syncBlocks: true, syncFailureCounts: true}

		// A failure of a blocked address is not taken before the one that set the
		// block (with a time from before the limiter's lock, that is a matter of
		// microseconds): it would end the block early.
		ipFailure := func(ip string) time.Time {
			failure := at()
			limiter.ipMu.RLock()
			defer limiter.ipMu.RUnlock()
			if blocked, ok := limiter.blockedIPs[ip]; ok && failure.Before(blocked.BlockedUntil.Add(-span)) {
				failure = blocked.BlockedUntil.Add(-span)
			}
			return failure
		}

		// the counters of each table, and the addresses with an active block
		type snapshot struct {
			pairs, ips, users map[string]counterTimes
			blocked           map[string]bool
		}
		take := func() snapshot {
			s := snapshot{pairs: map[string]counterTimes{}, ips: map[string]counterTimes{}, users: map[string]counterTimes{}, blocked: map[string]bool{}}
			limiter.ipUsernameMu.RLock()
			for key, info := range limiter.ipUsernameFailureCounts {
				s.pairs[key] = counterTimes{info.FirstFailure, info.LastFailure}
			}
			limiter.ipUsernameMu.RUnlock()
			limiter.ipMu.RLock()
			now := time.Now()
			for key, info := range limiter.ipFailureCounts {
				s.ips[key] = counterTimes{info.FirstFailure, info.LastFailure}
			}
			for key, blocked := range limiter.blockedIPs {
				s.blocked[key] = now.Before(blocked.BlockedUntil)
			}
			limiter.ipMu.RUnlock()
			limiter.usernameMu.RLock()
			for key, info := range limiter.usernameFailureCounts {
				s.users[key] = counterTimes{info.FirstFailure, info.LastFailure}
			}
			limiter.usernameMu.RUnlock()
			return s
		}

		for i := range ops {
			op := round*ops + i
			before := take()
			var ownPair, ownIP, ownUser string
			switch rng.IntN(10) {
			case 0, 1:
				ownIP, ownUser = ip(), user()
				ownPair = ownIP + "|" + ownUser
				limiter.updateIPUsernameFailure(ownIP, ownUser, at())
			case 2, 3:
				ownIP = ip()
				limiter.updateFailureTracking(ownIP, ipFailure(ownIP))
			case 4:
				ownUser = user()
				limiter.updateUsernameFailure(ownUser, at())
			case 5:
				ownIP, ownUser = ip(), user()
				ownPair = ownIP + "|" + ownUser
				limiter.RecordAuthAttempt(ctx, &StringAddr{Addr: ownIP}, ownUser, true)
			case 6:
				ownIP = ip()
				crl.handleFailureCount(RateLimitEvent{IP: ownIP, FailureCount: rng.IntN(5), LastDelay: time.Second, FirstFailure: at(), Timestamp: at()})
			case 7:
				ownUser = user()
				crl.handleUsernameFailure(RateLimitEvent{Username: ownUser, Timestamp: at()})
			case 8:
				ownIP = ip()
				crl.handleBlockIP(RateLimitEvent{IP: ownIP, BlockedUntil: at().Add(span), FailureCount: 3, FirstFailure: at(), Timestamp: at()})
			case 9:
				if rng.IntN(20) == 0 {
					limiter.cleanupExpiredEntries()
					after, cutoff := take(), time.Now().Add(-span)
					checkCleanup(t, op, "ip_username", before.pairs, after.pairs, cutoff)
					checkCleanup(t, op, "ip", before.ips, after.ips, cutoff)
					checkCleanup(t, op, "username", before.users, after.users, cutoff)
					continue
				}
				ownIP, ownUser = ip(), user()
				_ = limiter.CanAttemptAuth(ctx, &StringAddr{Addr: ownIP}, ownUser)
			}
			after := take()
			checkEviction(t, op, "ip_username", capacity, before.pairs, after.pairs, ownPair, nil)
			checkEviction(t, op, "ip", capacity, before.ips, after.ips, ownIP, before.blocked)
			checkEviction(t, op, "username", capacity, before.users, after.users, ownUser, nil)
		}
		limiter.Stop()
	}
}

// BenchmarkAuthFailureAtCapacity times a failed login whose keys are new to full tables,
// as in a spray of logins with distinct usernames from one address (a new key in the
// IP+username and username tables), or from distinct addresses (the IP table); with
// every tracked address blocked, the IP table has to pass over all of them.
func BenchmarkAuthFailureAtCapacity(b *testing.B) {
	discardAuthLimiterLogs(b)
	ctx := context.Background()
	for _, entries := range []int{1_000, 50_000} {
		b.Run(fmt.Sprintf("new_username/entries=%d", entries), func(b *testing.B) {
			cfg := DefaultAuthRateLimiterConfig()
			cfg.Enabled = true
			cfg.MaxAttemptsPerIP = math.MaxInt
			cfg.DelayStartThreshold = math.MaxInt
			cfg.MaxIPUsernameEntries, cfg.MaxUsernameEntries = entries, entries
			limiter := NewAuthRateLimiter("test", "", "", cfg)
			b.Cleanup(limiter.Stop)
			addr := &StringAddr{Addr: "192.0.2.1"}
			usernames := make([]string, 2*entries)
			for i := range usernames {
				usernames[i] = fmt.Sprintf("user%d@example.com", i)
			}
			for _, username := range usernames[:entries] {
				limiter.RecordAuthAttempt(ctx, addr, username, false)
			}
			i := entries
			for b.Loop() {
				limiter.RecordAuthAttempt(ctx, addr, usernames[i%len(usernames)], false)
				i++
			}
		})
		for _, blocked := range []bool{false, true} {
			name := fmt.Sprintf("new_ip/entries=%d", entries)
			if blocked {
				name = fmt.Sprintf("new_ip_all_blocked/entries=%d", entries)
			}
			b.Run(name, func(b *testing.B) {
				cfg := DefaultAuthRateLimiterConfig()
				cfg.Enabled = true
				cfg.MaxAttemptsPerIP = math.MaxInt
				if blocked {
					cfg.MaxAttemptsPerIP = 1
				}
				cfg.DelayStartThreshold = math.MaxInt
				cfg.MaxIPEntries = entries
				limiter := NewAuthRateLimiter("test", "", "", cfg)
				b.Cleanup(limiter.Stop)
				ips := make([]string, 2*entries)
				for i := range ips {
					ips[i] = trackingTables[1].key(i)
				}
				for _, ip := range ips[:entries] {
					limiter.updateFailureTracking(ip, time.Now())
				}
				i := entries
				for b.Loop() {
					limiter.updateFailureTracking(ips[i%len(ips)], time.Now())
					i++
				}
			})
		}
	}
}
