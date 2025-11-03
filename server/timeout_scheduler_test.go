package server

import (
	"runtime"
	"testing"
	"time"
)

func TestStopTimeoutScheduler(t *testing.T) {
	// Start the restartable scheduler using the manager API with a small interval
	if err := globalScheduler.Start(runtime.NumCPU(), 10*time.Millisecond); err != nil {
		t.Fatalf("failed to start global scheduler: %v", err)
	}

	// Give a small moment for shards to start
	time.Sleep(20 * time.Millisecond)

	// Stop scheduler using the package helper (which delegates to the manager)
	stopTimeoutScheduler()

	// If Stop returns without panic or blocking, we consider this a success for
	// the manager lifecycle test. The manager's internal state is private.
}
