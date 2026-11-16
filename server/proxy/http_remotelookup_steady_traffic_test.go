package proxy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/circuitbreaker"
)

// interval is configurable even though it defaults to zero. With a nonzero
// interval, a request replacing each timed-out request must not dilute the
// observed failure ratio with its result still pending.
func TestRemoteLookupConfiguredIntervalTripsOnSlowFailures(t *testing.T) {
	const interval = 100 * time.Millisecond
	client := NewHTTPRemoteLookupClient("http://localhost/lookup", time.Second, "", 143,
		false, false, false, false, false, false, false,
		&CircuitBreakerSettings{Interval: interval, Timeout: time.Hour, MinRequests: 3, FailureRatio: 0.6}, nil)
	start := func() func() {
		gate, done, admitted := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var once sync.Once
		finish := func() { once.Do(func() { close(gate) }); <-done }
		go func() {
			defer close(done)
			started := false
			_, _ = client.breaker.Execute(func() (any, error) {
				started = true
				close(admitted)
				<-gate
				return nil, context.DeadlineExceeded
			})
			if !started {
				close(admitted)
			}
		}()
		t.Cleanup(finish)
		select {
		case <-admitted:
		case <-time.After(5 * time.Second):
			t.Fatal("breaker did not admit or reject the request")
		}
		return finish
	}
	var original []func()
	for range 10 {
		original = append(original, start())
	}
	time.Sleep(interval + interval/2)
	for _, finish := range original {
		start() // the replacement starts before the previous request fails
		finish()
	}
	if got := client.breaker.State(); got != circuitbreaker.StateOpen {
		t.Fatalf("remote lookup breaker = %v after 10 slow failures, want OPEN; counts %+v", got, client.breaker.Counts())
	}
}
