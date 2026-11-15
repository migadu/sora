package resilient

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/storage"
)

// Against a blackholed or hung S3 endpoint every operation fails by its timeout (30s by
// default), long after the breaker's 10s counting window has rolled over. The S3
// breakers used to drop those results and never open, so every caller waited out the
// full timeout instead of failing fast (issue #464). The operations here fail after
// 10.5s, just past the window of the breakers as NewResilientS3Storage builds them.
func TestS3BreakersOpenOnFailuresSlowerThanInterval(t *testing.T) {
	if testing.Short() {
		t.Skip("waits past the breakers' 10s counting window")
	}
	t.Parallel()

	rs := NewResilientS3Storage(&storage.S3Storage{})
	for _, tc := range []struct {
		name    string
		breaker *circuitbreaker.CircuitBreaker
	}{
		{"get", rs.getBreaker},
		{"put", rs.putBreaker},
		{"delete", rs.deleteBreaker},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, _ = tc.breaker.Execute(func() (any, error) {
						time.Sleep(10500 * time.Millisecond)
						return nil, context.DeadlineExceeded
					})
				}()
			}
			wg.Wait()

			if state := tc.breaker.State(); state != circuitbreaker.StateOpen {
				t.Errorf("breaker is %s after 8 failed 10.5s operations, want %s (counts %+v)",
					state, circuitbreaker.StateOpen, tc.breaker.Counts())
			}
		})
	}
}
