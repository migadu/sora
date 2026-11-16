package circuitbreaker

import (
	"errors"
	"sync"
	"testing"
	"time"
)

var errSlow = errors.New("operation timed out")

// runBlocked starts one Execute per result, each blocked until release is closed, and
// returns once every request has passed beforeRequest. The returned function closes
// release and waits for all of them to finish.
func runBlocked(t *testing.T, cb *CircuitBreaker, results []error) (release func()) {
	t.Helper()
	gate := make(chan struct{})
	var started, done sync.WaitGroup
	for _, res := range results {
		started.Add(1)
		done.Add(1)
		go func(res error) {
			defer done.Done()
			_, _ = cb.Execute(func() (any, error) {
				started.Done()
				<-gate
				return nil, res
			})
		}(res)
	}
	started.Wait()
	return func() {
		close(gate)
		done.Wait()
	}
}

// The S3 and database breakers trip on a failure ratio and clear their counts every
// Interval while closed. Their operations time out after 30s or more, longer than the
// interval, so against a hung service every failure completes in a later window than
// it started in. Those results used to be dropped, and the breaker never opened
// (issue #464).
func TestFailuresSlowerThanIntervalOpenBreaker(t *testing.T) {
	settings := DefaultSettings("slow-failures")
	settings.Interval = 50 * time.Millisecond
	settings.OnStateChange = nil
	settings.ReadyToTrip = func(counts Counts) bool { // s3_get's rule
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 5 && failureRatio >= 0.6
	}
	cb := NewCircuitBreaker(settings)

	results := make([]error, 8)
	for i := range results {
		results[i] = errSlow
	}
	release := runBlocked(t, cb, results)
	time.Sleep(2 * settings.Interval) // every request outlives its counting window
	release()

	if state := cb.State(); state != StateOpen {
		t.Fatalf("breaker is %s after 8 failures slower than Interval, want %s (counts %+v)", state, StateOpen, cb.Counts())
	}
	if _, err := cb.Execute(func() (any, error) { return nil, nil }); !errors.Is(err, ErrCircuitBreakerOpen) {
		t.Fatalf("request after the breaker opened: err = %v, want %v", err, ErrCircuitBreakerOpen)
	}
}

// A result that arrives after the counting window rolled over is counted in the current
// window together with its request, so a failure ratio computed from the counts stays
// within 0..1.
func TestResultAfterWindowRolloverCountsWithItsRequest(t *testing.T) {
	cb := NewCircuitBreaker(Settings{
		Name:        "late-results",
		Interval:    50 * time.Millisecond,
		ReadyToTrip: func(Counts) bool { return false },
	})

	release := runBlocked(t, cb, []error{errSlow, errSlow, nil})
	time.Sleep(2 * 50 * time.Millisecond)
	release()

	got := cb.Counts()
	if got.Requests != 3 || got.TotalFailures != 2 || got.TotalSuccesses != 1 {
		t.Fatalf("counts after 3 results that outlived their window = %+v, want Requests:3 TotalFailures:2 TotalSuccesses:1", got)
	}

	// A request started in the current window is still counted only once.
	if _, err := cb.Execute(func() (any, error) { return nil, errSlow }); !errors.Is(err, errSlow) {
		t.Fatalf("Execute: err = %v, want %v", err, errSlow)
	}
	got = cb.Counts()
	if got.Requests != 4 || got.TotalFailures != 3 {
		t.Fatalf("counts after one more failure in the same window = %+v, want Requests:4 TotalFailures:3", got)
	}
}

// A result that arrives after the breaker changed state describes the service as it was
// before the change and is still dropped: a failure started while closed must not reopen
// a breaker that has since gone half-open to probe for recovery.
func TestResultAfterStateChangeIsDropped(t *testing.T) {
	cb := NewCircuitBreaker(Settings{
		Name:        "state-change",
		MaxRequests: 1,
		Interval:    time.Hour,
		Timeout:     time.Hour,
		ReadyToTrip: func(counts Counts) bool { return counts.ConsecutiveFailures >= 2 },
	})

	release := runBlocked(t, cb, []error{errSlow})
	for i := 0; i < 2; i++ {
		_, _ = cb.Execute(func() (any, error) { return nil, errSlow })
	}
	if state := cb.State(); state != StateOpen {
		t.Fatalf("breaker is %s after 2 consecutive failures, want %s", state, StateOpen)
	}
	cb.ForceHalfOpen()
	release()

	if state := cb.State(); state != StateHalfOpen {
		t.Fatalf("breaker is %s after a result from before it went half-open, want %s", state, StateHalfOpen)
	}
	if got := cb.Counts(); got != (Counts{}) {
		t.Fatalf("half-open counts = %+v, want none", got)
	}
}

// slowRequest is a request admitted by a breaker that blocks until fail is called.
type slowRequest struct {
	gate, done chan struct{}
}

// startSlow starts a request and returns once the breaker has admitted or refused it.
func startSlow(cb *CircuitBreaker) *slowRequest {
	r := &slowRequest{gate: make(chan struct{}), done: make(chan struct{})}
	decided := make(chan struct{})
	go func() {
		defer close(r.done)
		_, err := cb.Execute(func() (any, error) {
			close(decided)
			<-r.gate
			return nil, errSlow
		})
		if errors.Is(err, ErrCircuitBreakerOpen) || errors.Is(err, ErrTooManyRequests) {
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
func failSlowlyUnderSteadyTraffic(cb *CircuitBreaker, n int, outlive time.Duration) (State, Counts) {
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

// Under steady traffic against a hung service, as many requests start as fail in each
// counting window, and those that started are still in flight. A failure ratio taken
// over Requests counts them, so it stays at 0.5 while every result is a failure, and a
// breaker with a higher threshold never opened while the traffic went on.
func TestSlowFailuresUnderSteadyTrafficOpenBreaker(t *testing.T) {
	settings := DefaultSettings("steady-slow-failures")
	settings.Interval = 100 * time.Millisecond
	settings.OnStateChange = nil
	cb := NewCircuitBreaker(settings)

	state, counts := failSlowlyUnderSteadyTraffic(cb, 10, settings.Interval+settings.Interval/2)
	if state != StateOpen {
		t.Fatalf("breaker is %s after 10 slow failures under steady traffic, want %s (counts %+v)", state, StateOpen, counts)
	}
}
