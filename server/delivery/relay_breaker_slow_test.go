package delivery

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/circuitbreaker"
)

// slowFailure is longer than the 10-second counting window the relay breakers
// used to clear their counts on: an attempt that takes this long to fail
// straddles a window boundary.
const slowFailure = 10500 * time.Millisecond

// TestRelayCircuitBreakerOpensOnSlowFailures is #327: a relay that hangs until a
// timeout must open the breaker after the threshold of failed attempts, however
// long each attempt took to fail. The breaker used to clear its counts every 10
// seconds while closed and drop the result of any attempt that outlived that
// window, so a blackholed or hung relay (go-smtp's 30 s dial and 5 min command
// timeouts, the HTTP relay's 30 s) never opened it.
func TestRelayCircuitBreakerOpensOnSlowFailures(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for relay attempts that take over 10 seconds to fail")
	}
	cbConfig := CircuitBreakerConfig{Threshold: 2, Timeout: time.Minute, MaxRequests: 1}

	t.Run("smtp", func(t *testing.T) {
		t.Parallel()
		// A relay that answers its greeting only after the window has passed, and
		// then with a temporary refusal.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					time.Sleep(slowFailure)
					_, _ = conn.Write([]byte("421 4.3.2 Service not available\r\n"))
				}()
			}
		}()

		handler := NewRelayHandlerFromConfig("smtp", ln.Addr().String(), "", "", "test",
			false, false, false, "", "", "", &testLogger{}, cbConfig)
		assertSlowFailuresOpenBreaker(t, handler, handler.(*SMTPRelayHandler).CircuitBreaker, cbConfig.Threshold)
	})

	t.Run("http", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(slowFailure):
			case <-r.Context().Done():
			}
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		handler := NewRelayHandlerFromConfig("http", "", srv.URL, "token", "test",
			false, false, false, "", "", "", &testLogger{}, cbConfig)
		assertSlowFailuresOpenBreaker(t, handler, handler.(*HTTPRelayHandler).CircuitBreaker, cbConfig.Threshold)
	})
}

// assertSlowFailuresOpenBreaker runs threshold concurrent attempts against a relay
// that fails each of them slowly, as the relay worker's concurrent deliveries do,
// and checks that the breaker is then open and the next attempt fails fast.
func assertSlowFailuresOpenBreaker(t *testing.T, handler RelayHandler, cb *circuitbreaker.CircuitBreaker, threshold int) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make([]error, threshold)
	for i := range threshold {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = handler.SendToExternalRelay("sender@example.com", "recipient@example.org", []byte("Subject: hi\r\n\r\nbody\r\n"))
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err == nil || IsPermanentError(err) {
			t.Fatalf("attempt %d: want a temporary failure, got %v", i, err)
		}
	}

	if state := cb.State(); state != circuitbreaker.StateOpen {
		t.Fatalf("breaker is %s after %d failed attempts, want OPEN (counts %+v)", state, threshold, cb.Counts())
	}
	start := time.Now()
	err := handler.SendToExternalRelay("sender@example.com", "recipient@example.org", []byte("Subject: hi\r\n\r\nbody\r\n"))
	if !errors.Is(err, circuitbreaker.ErrCircuitBreakerOpen) {
		t.Fatalf("next attempt: want the open breaker's error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("next attempt took %v, want it to fail fast", elapsed)
	}
}
