package server

import (
	"fmt"
	"hash/fnv"
	"runtime"
	"sync"
	"time"

	"github.com/migadu/sora/pkg/metrics"
)

// timeoutShard manages timeout checking for a subset of connections
type timeoutShard struct {
	conns          map[*SoraConn]struct{}
	mu             sync.RWMutex
	ticker         *time.Ticker
	quit           chan struct{}
	wg             sync.WaitGroup
	snapshotBuffer []*SoraConn // Reusable buffer to reduce allocations
	id             int
}

// loop runs the timeout checker for this shard
func (s *timeoutShard) loop() {
	defer s.wg.Done()
	shardID := fmt.Sprintf("%d", s.id)

	for {
		select {
		case <-s.ticker.C:
			checkStart := time.Now()
			s.mu.RLock()
			// Reuse snapshot buffer to avoid allocations
			s.snapshotBuffer = s.snapshotBuffer[:0]
			if cap(s.snapshotBuffer) < len(s.conns) {
				s.snapshotBuffer = make([]*SoraConn, 0, len(s.conns))
			}
			for conn := range s.conns {
				s.snapshotBuffer = append(s.snapshotBuffer, conn)
			}
			conns := s.snapshotBuffer
			connCount := len(s.conns)
			s.mu.RUnlock()

			// Update connection count metric
			metrics.TimeoutSchedulerConnectionsTotal.WithLabelValues(shardID).Set(float64(connCount))

			// Check timeouts for each connection
			for _, conn := range conns {
				conn.checkTimeouts(time.Now())
			}

			// Record check duration
			checkDuration := time.Since(checkStart).Seconds()
			metrics.TimeoutSchedulerCheckDuration.WithLabelValues(shardID).Observe(checkDuration)

		case <-s.quit:
			s.ticker.Stop()
			return
		}
	}
}

// TimeoutScheduler manages lifecycle of timeout shards and provides
// register/unregister APIs for connections. It is restartable.
type TimeoutScheduler struct {
	mu         sync.Mutex
	shards     []*timeoutShard
	shardCount int
	interval   time.Duration
	running    bool
}

var globalScheduler = &TimeoutScheduler{}

// DefaultTimeoutSchedulerInterval controls the tick interval used when the
// scheduler is started via StartDefault. Tests may override this by calling
// the public Start method with a custom interval.
var DefaultTimeoutSchedulerInterval = 100 * time.Millisecond

// stopTimeoutScheduler stops the global scheduler.
func stopTimeoutScheduler() {
	_ = globalScheduler.Stop()
}

// StartDefault starts the scheduler with default shard count and interval.
func (s *TimeoutScheduler) StartDefault() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil
	}

	shardCount := computeShardCount(0)
	interval := DefaultTimeoutSchedulerInterval
	return s.start(shardCount, interval)
}

// Start starts the scheduler with the requested shard count and interval.
// shardCount can be:
//   - 0: uses runtime.NumCPU() (logical cores including hyperthreading)
//   - -1: uses runtime.NumCPU()/2 (approximates physical cores)
//   - >0: uses the specified value
//
// It is safe to call multiple times; subsequent calls when running are no-ops.
func (s *TimeoutScheduler) Start(shardCount int, interval time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil
	}
	if shardCount < -1 {
		return fmt.Errorf("invalid shard count: %d (must be >= -1)", shardCount)
	}
	computed := computeShardCount(shardCount)
	return s.start(computed, interval)
}

func (s *TimeoutScheduler) start(shardCount int, interval time.Duration) error {
	// assume caller holds s.mu
	if s.running {
		return nil
	}

	s.shardCount = shardCount
	s.interval = interval
	s.shards = make([]*timeoutShard, shardCount)

	for i := 0; i < shardCount; i++ {
		shard := &timeoutShard{
			conns:  make(map[*SoraConn]struct{}),
			ticker: time.NewTicker(interval),
			quit:   make(chan struct{}),
			id:     i,
		}
		s.shards[i] = shard
		shard.wg.Add(1)
		go shard.loop()
	}

	s.running = true
	return nil
}

// Stop stops all shards and waits for goroutines to exit.
func (s *TimeoutScheduler) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}

	// Signal shards to stop
	for _, shard := range s.shards {
		if shard == nil {
			continue
		}
		select {
		case <-shard.quit:
			// already closed
		default:
			close(shard.quit)
		}
	}

	// Wait for each shard's goroutine
	for _, shard := range s.shards {
		if shard != nil {
			shard.wg.Wait()
		}
	}

	// clear internal state
	s.shards = nil
	s.shardCount = 0
	s.running = false

	s.mu.Unlock()
	return nil
}

// selectShardIndex returns shard index for remoteAddr using FNV hashing
func (s *TimeoutScheduler) selectShardIndex(remoteAddr string) int {
	if s.shardCount <= 0 {
		return 0
	}
	h := fnv.New32a()
	h.Write([]byte(remoteAddr))
	return int(h.Sum32()) % s.shardCount
}

// Register registers connection c with the scheduler. It auto-starts the
// scheduler if not running. Requires c.remoteAddr to be set.
func (s *TimeoutScheduler) Register(c *SoraConn) {
	if c == nil || c.remoteAddr == "" {
		return
	}

	// ensure running
	s.mu.Lock()
	if !s.running {
		// start with defaults
		_ = s.start(computeShardCount(0), 100*time.Millisecond)
	}

	shardIdx := s.selectShardIndex(c.remoteAddr)
	shard := s.shards[shardIdx]
	// must hold shard lock to mutate conns
	shard.mu.Lock()
	shard.conns[c] = struct{}{}
	connCount := len(shard.conns)
	shard.mu.Unlock()
	s.mu.Unlock()

	// Update metric
	metrics.TimeoutSchedulerConnectionsTotal.WithLabelValues(fmt.Sprintf("%d", shardIdx)).Set(float64(connCount))

	// Immediately trigger a check for this connection in a goroutine. This
	// ensures short absolute timeouts are detected without waiting for the
	// shard ticker to fire (helps tests and fast timeouts).
	go func(conn *SoraConn) {
		conn.checkTimeouts(time.Now())
	}(c)
}

// Unregister removes connection c from scheduler. Safe to call if scheduler stopped.
func (s *TimeoutScheduler) Unregister(c *SoraConn) {
	if c == nil || c.remoteAddr == "" {
		return
	}

	s.mu.Lock()
	if !s.running || s.shardCount == 0 || s.shards == nil {
		s.mu.Unlock()
		return
	}

	shardIdx := s.selectShardIndex(c.remoteAddr)
	if shardIdx < 0 || shardIdx >= len(s.shards) {
		s.mu.Unlock()
		return
	}
	shard := s.shards[shardIdx]
	if shard == nil {
		s.mu.Unlock()
		return
	}

	shard.mu.Lock()
	delete(shard.conns, c)
	connCount := len(shard.conns)
	shard.mu.Unlock()
	metrics.TimeoutSchedulerConnectionsTotal.WithLabelValues(fmt.Sprintf("%d", shardIdx)).Set(float64(connCount))
	s.mu.Unlock()
}

// computeShardCount computes the actual shard count based on the input value:
//   - 0: runtime.NumCPU() (logical cores)
//   - -1: runtime.NumCPU()/2 (approximates physical cores)
//   - >0: use as-is
func computeShardCount(shardCount int) int {
	switch shardCount {
	case 0:
		return max(runtime.NumCPU(), 1)
	case -1:
		return max(runtime.NumCPU()/2, 1)
	}
	return max(shardCount, 1)
}

// InitializeGlobalTimeoutScheduler initializes the global timeout scheduler with the specified shard count.
// This should be called once at application startup before any servers start accepting connections.
// shardCount can be:
//   - 0: uses runtime.NumCPU() (logical cores including hyperthreading)
//   - -1: uses runtime.NumCPU()/2 (approximates physical cores)
//   - >0: uses the specified value
func InitializeGlobalTimeoutScheduler(shardCount int) error {
	if shardCount < -1 {
		return fmt.Errorf("invalid shard count: %d (must be >= -1)", shardCount)
	}
	computed := computeShardCount(shardCount)
	return globalScheduler.Start(computed, DefaultTimeoutSchedulerInterval)
}

// Package-level helpers used by other files
func registerConn(c *SoraConn) {
	globalScheduler.Register(c)
}

func unregisterConn(c *SoraConn) {
	globalScheduler.Unregister(c)
}
