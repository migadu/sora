package server

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestConcurrentRegisterUnregisterDuringStop stresses the TimeoutScheduler by
// running many concurrent Register/Unregister operations while Stop is called
// repeatedly. The test passes if no panics or data-races (use -race) occur and
// the operations complete within the timeout.
func TestConcurrentRegisterUnregisterDuringStop(t *testing.T) {
	// Start the scheduler with a small interval for the test
	if err := globalScheduler.Start(runtime.NumCPU(), 10*time.Millisecond); err != nil {
		t.Fatalf("failed to start scheduler: %v", err)
	}

	var wg sync.WaitGroup
	stopCh := make(chan struct{})

	// Start N workers that rapidly register/unregister connections
	workers := 50
	opsPerWorker := 200

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < opsPerWorker; i++ {
				// Use a small set of remote addrs to hit multiple shards
				addr := fmt.Sprintf("10.0.%d.%d:1%d", id%8, i%16, i%10)
				c := &SoraConn{remoteAddr: addr}
				registerConn(c)
				// short sleep to increase chance of interleaving
				time.Sleep(time.Millisecond)
				unregisterConn(c)
				select {
				case <-stopCh:
					return
				default:
				}
			}
		}(w)
	}

	// Stopper goroutine: call stopTimeoutScheduler repeatedly while workers run
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		// Run stops for a short duration
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			<-ticker.C
			stopTimeoutScheduler()
			// small pause to let other goroutines proceed
			time.Sleep(2 * time.Millisecond)
			// restart scheduler to allow further register calls
			_ = globalScheduler.Start(runtime.NumCPU(), 10*time.Millisecond)
		}
	}()

	// Wait for workers to finish
	wg.Wait()
	close(stopCh)

	// Ensure scheduler is running at end for cleanup
	_ = globalScheduler.Start(runtime.NumCPU(), 10*time.Millisecond)
	// Stop cleanly
	stopTimeoutScheduler()
}
