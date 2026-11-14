package resilient

import (
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/db"
	"github.com/migadu/sora/logger"
)

// attemptReconnectFailedHosts swaps the pool slices at runtime: it adds a write host that
// was down at startup, and the first replica that connects replaces the write hosts as
// the read pools. Operations failing over at that moment must pick from the pools as they
// are now: a goroutine that went on with the slice it read before the swap indexed past
// the end of it, or stored an index into the old slice that every later operation then
// used on the new one, and panicked with "index out of range".
func TestGetHealthyDatabaseWithFailover_PoolsSwappedDuringFailover(t *testing.T) {
	prev := logger.Swap(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { logger.Swap(prev) })

	newPool := func(host string, healthy bool) *DatabasePool {
		p := &DatabasePool{database: &db.Database{}, host: host}
		p.isHealthy.Store(healthy)
		return p
	}

	tests := []struct {
		name string
		// start returns a manager as startup leaves it; swap changes it the way
		// attemptReconnectFailedHosts does, with fm.mu held.
		start func() *RuntimeFailoverManager
		swap  func(fm *RuntimeFailoverManager)
	}{
		{
			name: "write host added",
			start: func() *RuntimeFailoverManager {
				fm := &RuntimeFailoverManager{writePools: []*DatabasePool{newPool("pg-a.example.com", false)}}
				fm.readPools = fm.writePools
				fm.readsUseWritePools.Store(true)
				return fm
			},
			swap: func(fm *RuntimeFailoverManager) {
				fm.writePools = append(fm.writePools[:1:1], newPool("pg-b.example.com", true))
				fm.readPools = fm.writePools
			},
		},
		{
			name: "first replica replaces the write hosts for reads",
			start: func() *RuntimeFailoverManager {
				fm := &RuntimeFailoverManager{writePools: []*DatabasePool{
					newPool("pg-a.example.com", false), newPool("pg-b.example.com", true),
				}}
				fm.readPools = fm.writePools
				fm.readsUseWritePools.Store(true)
				return fm
			},
			swap: func(fm *RuntimeFailoverManager) {
				fm.readPools = []*DatabasePool{newPool("replica.example.com", true)}
				fm.currentReadIdx.Store(0)
				fm.readsUseWritePools.Store(false)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var current atomic.Pointer[ResilientDatabase]
			current.Store(&ResilientDatabase{failoverManager: tc.start()})

			var stop atomic.Bool
			var panicked atomic.Value
			var wg sync.WaitGroup
			for w := 0; w < 2*runtime.GOMAXPROCS(0)+2; w++ {
				isWrite := w%2 == 0
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer func() {
						if r := recover(); r != nil {
							panicked.Store(fmt.Sprint(r))
							stop.Store(true)
						}
					}()
					for !stop.Load() {
						current.Load().getHealthyDatabaseWithFailover(isWrite)
					}
				}()
			}

			// Each round starts a fresh manager and swaps its pools once, as a reconnect does.
			// A panic in the fast path leaves fm.mu read-locked for good, so the lock is
			// taken with a timeout.
			deadline := time.Now().Add(time.Second)
			for !stop.Load() && time.Now().Before(deadline) {
				fm := tc.start()
				current.Store(&ResilientDatabase{failoverManager: fm})
				runtime.Gosched()
				locked := make(chan struct{})
				go func() { fm.mu.Lock(); close(locked) }()
				select {
				case <-locked:
				case <-time.After(5 * time.Second):
					t.Errorf("the failover lock was never released")
					stop.Store(true)
					continue
				}
				tc.swap(fm)
				fm.mu.Unlock()
				runtime.Gosched()
			}
			stop.Store(true)
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				// The panicking goroutine left fm.mu locked: the others wait forever.
				t.Errorf("operations still blocked on the failover lock 10s after the last swap")
			}

			if r := panicked.Load(); r != nil {
				t.Fatalf("failover panicked while the pools were swapped: %v", r)
			}
		})
	}
}
