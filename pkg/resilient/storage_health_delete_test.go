// ============================================================
// FILE 1 (primary): pkg/resilient/storage_health_delete_test.go
// ============================================================
package resilient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/circuitbreaker"
	"github.com/migadu/sora/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsHealthyObservesDeleteBreaker proves (or disproves) that
// ResilientS3Storage.IsHealthy() is blind to S3 delete-path failures.
//
// IsHealthy() is documented as "Used by the cleaner to skip destructive
// operations when S3 is down" (pkg/resilient/storage.go:291-296), and the
// cleaner's only S3 traffic is DeleteWithRetry (server/cleaner/worker.go:331).
// If IsHealthy() only consults the put/get breakers, the cleaner's own S3
// activity can never move it: the guard is dead code.
//
// The test drives real DELETE traffic against an S3 endpoint that returns
// HTTP 500 until the DELETE circuit breaker is OPEN (i.e. the resilient layer
// itself has concluded that S3 deletes are failing), and then asks
// IsHealthy().
//
// Expected correct behaviour: IsHealthy() == false.
// RED result (defect confirmed):  IsHealthy() == true.
func TestIsHealthyObservesDeleteBreaker(t *testing.T) {
	var deleteCount, putCount, getCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			atomic.AddInt32(&deleteCount, 1)
		case http.MethodPut:
			atomic.AddInt32(&putCount, 1)
		case http.MethodGet, http.MethodHead:
			atomic.AddInt32(&getCount, 1)
		}
		// Total S3 outage: every request is a 5xx.
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	s3storage, err := storage.New(
		strings.TrimPrefix(server.URL, "http://"),
		"test-access-key",
		"test-secret-key",
		"test-bucket",
		false, // useSSL
		false, // debug
		5*time.Second,
	)
	require.NoError(t, err)

	rs := NewResilientS3Storage(s3storage)

	// Sanity: a fresh wrapper is healthy and all breakers are closed.
	require.True(t, rs.IsHealthy(), "precondition: fresh wrapper should report healthy")
	require.Equal(t, circuitbreaker.StateClosed, rs.GetDeleteBreakerState())

	// Drive DELETE traffic — exactly what the cleaner does — until the DELETE
	// breaker trips. deleteSettings trips at >=3 requests with >=50% failures,
	// so a single DeleteWithRetry (1 attempt + 3 retries) is normally enough.
	ctx := context.Background()
	deadline := time.Now().Add(60 * time.Second)
	for rs.GetDeleteBreakerState() != circuitbreaker.StateOpen && time.Now().Before(deadline) {
		err := rs.DeleteWithRetry(ctx, "cleanup/candidate-object")
		require.Error(t, err, "DELETE against a 500-only endpoint must fail")
	}

	// Precondition for the real assertion: the resilient layer has definitively
	// classified the S3 delete path as broken.
	require.Equal(t, circuitbreaker.StateOpen, rs.GetDeleteBreakerState(),
		"precondition: DELETE circuit breaker must be OPEN before checking IsHealthy()")
	require.Greater(t, atomic.LoadInt32(&deleteCount), int32(0),
		"precondition: real DELETE requests must have reached the failing endpoint")

	// The cleaner only ever issues deletes, so put/get breakers stay untouched.
	assert.Equal(t, int32(0), atomic.LoadInt32(&putCount), "no PUT traffic was issued")
	assert.Equal(t, int32(0), atomic.LoadInt32(&getCount), "no GET/HEAD traffic was issued")
	assert.Equal(t, circuitbreaker.StateClosed, rs.GetPutBreakerState(),
		"PUT breaker is untouched by delete-only traffic")
	assert.Equal(t, circuitbreaker.StateClosed, rs.GetGetBreakerState(),
		"GET breaker is untouched by delete-only traffic")

	// THE ASSERTION UNDER TEST.
	assert.False(t, rs.IsHealthy(),
		"IsHealthy() must report unhealthy when the DELETE circuit breaker is OPEN; "+
			"it currently only consults putBreaker/getBreaker, so the cleaner's S3 "+
			"health guard can never observe delete-path failure (dead code)")
}

// newFlakyS3 returns a wrapper over an S3 endpoint that 500s while broken is true and
// otherwise answers 404 (nothing has ever been written to it), plus counters for the
// requests it received by method.
func newFlakyS3(t *testing.T, broken *atomic.Bool, deleteCount, statCount *int32) *ResilientS3Storage {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodDelete:
			atomic.AddInt32(deleteCount, 1)
		case http.MethodHead, http.MethodGet:
			atomic.AddInt32(statCount, 1)
		}
		if broken.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	s3storage, err := storage.New(
		strings.TrimPrefix(server.URL, "http://"),
		"test-access-key", "test-secret-key", "test-bucket",
		false, false, 5*time.Second,
	)
	require.NoError(t, err)

	return NewResilientS3Storage(s3storage)
}

// tripDeleteBreaker drives the cleaner's only S3 operation until the DELETE breaker opens.
func tripDeleteBreaker(t *testing.T, rs *ResilientS3Storage) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(60 * time.Second)
	for rs.GetDeleteBreakerState() != circuitbreaker.StateOpen && time.Now().Before(deadline) {
		require.Error(t, rs.DeleteWithRetry(ctx, "cleanup/candidate-object"), "DELETE against a 500-only endpoint must fail")
	}
	require.Equal(t, circuitbreaker.StateOpen, rs.GetDeleteBreakerState(),
		"precondition: the DELETE circuit breaker must be OPEN")
}

// TestIsHealthyResolvesStaleHalfOpenBreaker is the other direction of the same guard.
// An OPEN breaker decays to half-open after its 30s timeout, and pkg/circuitbreaker only
// leaves half-open on a SUCCESSFUL request. The cleaner's ResilientS3Storage is its own
// instance whose only traffic is DeleteWithRetry, so on a deployment where Phase 1 finds
// no delete candidates nothing ever probes the breaker.
//
// Expected correct behaviour: IsHealthy() resolves the half-open breaker against the
// recovered S3 and reports healthy.
// RED result (defect confirmed): IsHealthy() stays false forever, so CleanupFailedUploads
// — a DB-only operation — is skipped indefinitely long after S3 recovered.
func TestIsHealthyResolvesStaleHalfOpenBreaker(t *testing.T) {
	var broken atomic.Bool
	broken.Store(true)
	var deleteCount, statCount int32

	rs := newFlakyS3(t, &broken, &deleteCount, &statCount)
	tripDeleteBreaker(t, rs)
	require.False(t, rs.IsHealthy(), "precondition: an open DELETE breaker means unhealthy")

	// S3 comes back. With no traffic of its own the breaker only decays to half-open on
	// its timeout; ForceHalfOpen reaches that exact state without the 30s wait.
	broken.Store(false)
	deletesBeforeProbe := atomic.LoadInt32(&deleteCount)
	rs.deleteBreaker.ForceHalfOpen()
	require.Equal(t, circuitbreaker.StateHalfOpen, rs.GetDeleteBreakerState())

	assert.True(t, rs.IsHealthy(),
		"IsHealthy() must resolve a half-open breaker instead of reporting unhealthy forever: "+
			"half-open has no time-based exit, and the cleaner's wrapper issues no S3 request "+
			"of its own until it has delete candidates again")
	assert.Equal(t, circuitbreaker.StateClosed, rs.GetDeleteBreakerState(),
		"a successful liveness probe must close the half-open breaker")
	assert.Equal(t, deletesBeforeProbe, atomic.LoadInt32(&deleteCount),
		"the liveness probe must not issue destructive requests")
	assert.Greater(t, atomic.LoadInt32(&statCount), int32(0),
		"the liveness probe must actually reach S3 rather than assume recovery")
}

// TestIsHealthyStaysUnhealthyWhileHalfOpenAndS3Down is the safety side of the same
// behaviour: resolving a half-open breaker must never degrade into treating half-open as
// healthy, which would re-enable destructive cleanup in the middle of an S3 outage.
func TestIsHealthyStaysUnhealthyWhileHalfOpenAndS3Down(t *testing.T) {
	var broken atomic.Bool
	broken.Store(true)
	var deleteCount, statCount int32

	rs := newFlakyS3(t, &broken, &deleteCount, &statCount)
	tripDeleteBreaker(t, rs)

	rs.deleteBreaker.ForceHalfOpen()
	require.Equal(t, circuitbreaker.StateHalfOpen, rs.GetDeleteBreakerState())

	assert.False(t, rs.IsHealthy(),
		"S3 is still down, so a half-open breaker must not be reported as healthy")
	assert.Equal(t, circuitbreaker.StateOpen, rs.GetDeleteBreakerState(),
		"a failed liveness probe must reopen the breaker for another timeout")
}

// =========================================================================
