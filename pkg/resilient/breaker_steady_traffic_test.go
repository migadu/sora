package resilient

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/storage"
)

// slowRequest is a request admitted by a breaker that blocks until fail is called.
type slowRequest struct {
	gate, done chan struct{}
}

// startSlow starts a request that will fail with a timeout and returns once the breaker
// has admitted or refused it.
func startSlow(cb *circuitbreaker.CircuitBreaker) *slowRequest {
	r := &slowRequest{gate: make(chan struct{}), done: make(chan struct{})}
	decided := make(chan struct{})
	go func() {
		defer close(r.done)
		_, err := cb.Execute(func() (any, error) {
			close(decided)
			<-r.gate
			return nil, context.DeadlineExceeded
		})
		if errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) || errors.Is(err, circuitbreaker.ErrTooManyRequests) {
			close(decided)
		}
	}()
	<-decided
	return r
}

// fail makes the request fail and waits until the breaker has counted the result.
func (r *slowRequest) fail() {
	close(r.gate)
	<-r.done
}

// failSlowlyUnderSteadyTraffic models a hung service under steady traffic: n requests
// are in flight when the counting window rolls over (after outlive), then each fails in
// turn just after the request that replaces it (a client retrying, the next client) has
// started. It returns the breaker's state and counts once those n results are in.
func failSlowlyUnderSteadyTraffic(cb *circuitbreaker.CircuitBreaker, n int, outlive time.Duration) (circuitbreaker.State, circuitbreaker.Counts) {
	inFlight := make([]*slowRequest, n)
	for i := range inFlight {
		inFlight[i] = startSlow(cb)
	}
	time.Sleep(outlive)

	replacements := make([]*slowRequest, 0, n)
	for _, r := range inFlight {
		replacements = append(replacements, startSlow(cb))
		r.fail()
	}
	state, counts := cb.State(), cb.Counts()
	for _, r := range replacements {
		r.fail()
	}
	return state, counts
}

// Against a hung S3 endpoint under steady traffic, each counting window has as many
// operations starting as timing out, and the ones that started are still in flight. A
// failure ratio over Requests counted them and stayed at 0.5 while every result was a
// failure: below the GET breaker's 60%, so it stayed closed while traffic went on.
func TestS3BreakersOpenOnSlowFailuresUnderSteadyTraffic(t *testing.T) {
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
			state, counts := failSlowlyUnderSteadyTraffic(tc.breaker, 10, 10500*time.Millisecond)
			if state != circuitbreaker.StateOpen {
				t.Errorf("breaker is %s after 10 timeouts under steady traffic, want %s (counts %+v)",
					state, circuitbreaker.StateOpen, counts)
			}
		})
	}
}

// The same for the database breakers' trip rules, whose operations time out after
// query_timeout (30s) or search_timeout (60s) against a 15s query window, and after
// write_timeout (10s) against a 10s write window. The interval is shortened here; only
// the rule is under test.
func TestDatabaseBreakersOpenOnSlowFailuresUnderSteadyTraffic(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule func(circuitbreaker.Counts) bool
	}{
		{"query", queryBreakerReadyToTrip},
		{"write", writeBreakerReadyToTrip},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const interval = 100 * time.Millisecond
			cb := circuitbreaker.NewCircuitBreaker(circuitbreaker.Settings{
				Name:        "database_" + tc.name,
				MaxRequests: databaseBreakerMaxRequests,
				Interval:    interval,
				Timeout:     time.Hour,
				ReadyToTrip: tc.rule,
			})
			state, counts := failSlowlyUnderSteadyTraffic(cb, 10, interval+interval/2)
			if state != circuitbreaker.StateOpen {
				t.Errorf("breaker is %s after 10 timeouts under steady traffic, want %s (counts %+v)",
					state, circuitbreaker.StateOpen, counts)
			}
		})
	}
}

// Taking the ratio over results must not let a few failures trip a breaker just because
// many requests are in flight: the minimum is a number of results, too.
func TestDatabaseBreakerRulesNeedEnoughResults(t *testing.T) {
	if queryBreakerReadyToTrip(circuitbreaker.Counts{Requests: 50, TotalFailures: 7, ConsecutiveFailures: 7}) {
		t.Error("query breaker trips on 7 failed results, want at least 8")
	}
	if writeBreakerReadyToTrip(circuitbreaker.Counts{Requests: 50, TotalFailures: 4, ConsecutiveFailures: 4}) {
		t.Error("write breaker trips on 4 failed results, want at least 5")
	}
	if !queryBreakerReadyToTrip(circuitbreaker.Counts{Requests: 50, TotalFailures: 8, ConsecutiveFailures: 8}) {
		t.Error("query breaker does not trip on 8 failed results of 8")
	}
	if queryBreakerReadyToTrip(circuitbreaker.Counts{Requests: 50, TotalSuccesses: 6, TotalFailures: 8}) {
		t.Error("query breaker trips at a 57% failure ratio, want 60%")
	}
}
