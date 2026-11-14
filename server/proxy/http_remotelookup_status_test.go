package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/circuitbreaker"
)

func newStatusLookupClient(t *testing.T, status int) *HTTPRemoteLookupClient {
	t.Helper()
	lookup := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error": "lookup refused"}`, status)
	}))
	t.Cleanup(lookup.Close)
	return NewHTTPRemoteLookupClient(lookup.URL+"/lookup?email=$email", 2*time.Second, "", 143,
		false, false, false, false, false, false, false,
		&CircuitBreakerSettings{MaxRequests: 1, Timeout: time.Minute, FailureRatio: 0.6, MinRequests: 3}, nil)
}

// 408 and 429 describe the lookup service (timing out, rate-limiting this proxy) as 5xx
// do, so they count toward the circuit breaker, whose open state is the backing off a 429
// asks for. Any other 4xx is a refusal of this one request: a temporary failure for the
// login, but it must not let the answers for one address open the breaker for every user.
func TestHTTPRemoteLookupBreakerCountsOverloadNotRefusedRequests(t *testing.T) {
	for _, c := range []struct {
		status   int
		wantOpen bool
	}{
		{http.StatusServiceUnavailable, true},
		{http.StatusRequestTimeout, true},
		{http.StatusTooManyRequests, true},
		{http.StatusBadRequest, false},
		{http.StatusUnprocessableEntity, false},
	} {
		t.Run(http.StatusText(c.status), func(t *testing.T) {
			client := newStatusLookupClient(t, c.status)
			for i := 0; i < 5; i++ {
				_, result, err := client.LookupUserRoute(context.Background(), "anna@example.com", "secret")
				if result != AuthTemporarilyUnavailable || !errors.Is(err, ErrRemoteLookupTransient) {
					t.Fatalf("lookup %d answered %d: result %v, err %v; want AuthTemporarilyUnavailable, ErrRemoteLookupTransient", i+1, c.status, result, err)
				}
			}
			if open := client.breaker.State() == circuitbreaker.StateOpen; open != c.wantOpen {
				t.Errorf("after 5 answers %d the circuit breaker is %v, want open=%v", c.status, client.breaker.State(), c.wantOpen)
			}
		})
	}
}

// The routing lookup (LMTP recipients, routing after a local login) must not read a 4xx
// as "no such user": LMTP would answer a permanent 550 (or deliver through the local
// database) for a lookup service that is only rate-limiting, and with named pools the
// user would be routed into the default pool instead of being refused.
func TestRoutingLookupRefusalIsNotUserNotFound(t *testing.T) {
	for _, status := range []int{http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusBadRequest} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client := newStatusLookupClient(t, status)
			flat, err := NewConnectionManagerWithRouting([]string{"10.0.0.1:24"}, 24, false, false, false, time.Second, client, "lmtp-test")
			if err != nil {
				t.Fatal(err)
			}
			info, err := flat.LookupUserRoute(context.Background(), "anna@example.com")
			if !errors.Is(err, ErrRemoteLookupTransient) {
				t.Errorf("LookupUserRoute after a %d: info %+v, err %v; want ErrRemoteLookupTransient, not user-not-found", status, info, err)
			}

			pools, err := NewConnectionManagerWithPools(testPoolSpecs(), 143, time.Second, newStatusLookupClient(t, status), "pools-test", true)
			if err != nil {
				t.Fatal(err)
			}
			res, err := DetermineRoute(RouteParams{
				Ctx: context.Background(), Username: "anna@example.com", Protocol: "lmtp",
				ConnManager: pools, ProxyName: "test",
			})
			if !errors.Is(err, ErrRouteLookupFailed) {
				t.Errorf("named pools, lookup answered %d: routed to %q (pool %q), err %v; want ErrRouteLookupFailed", status, res.PreferredAddr, res.Pool, err)
			}
		})
	}
}
