package proxy

import (
	"context"
	"testing"
	"time"
)

// A process can resume after both timers have expired. Elapsed wall time does
// not give a backend the connect_timeout that a shorter caller deadline denied.
func TestLateCallerDeadlineDoesNotBecomeBackendTimeout(t *testing.T) {
	phaseStart := time.Now().Add(-3 * time.Second)
	cm := &ConnectionManager{connectTimeout: time.Second}
	for _, tc := range []struct {
		name         string
		callerBudget time.Duration
		want         bool
	}{
		{"caller cut phase short", 500 * time.Millisecond, false},
		{"backend received full phase", 2 * time.Second, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithDeadline(context.Background(), phaseStart.Add(tc.callerBudget))
			defer cancel()
			if got := cm.phaseExhaustedConnectTimeout(ctx, phaseStart); got != tc.want {
				t.Fatalf("late timeout observation: caller budget %v, connect_timeout 1s, charge backend=%v; want %v", tc.callerBudget, got, tc.want)
			}
		})
	}
}
