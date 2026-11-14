package delivery

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// connCountingServer starts an httptest server that counts the connections it
// accepts (opened) and those still open (open).
func connCountingServer(t *testing.T, h http.HandlerFunc) (srv *httptest.Server, opened, open *atomic.Int32) {
	t.Helper()
	opened, open = new(atomic.Int32), new(atomic.Int32)
	srv = httptest.NewUnstartedServer(h)
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			opened.Add(1)
			open.Add(1)
		case http.StateClosed, http.StateHijacked:
			open.Add(-1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, opened, open
}

// TestHTTPRelayHandlerReusesConnections is #461: the HTTP relay built a new
// http.Client and http.Transport for every message. Nothing ever reused a
// connection, and when the relay answered with an empty body (204, or a 2xx with
// Content-Length: 0) the connection went idle in a transport nothing referenced,
// with no idle timeout: every message left a TCP connection and its goroutines
// behind until the relay server closed it. One handler must keep one client for
// its lifetime and drain each response, so sequential sends share one connection
// whatever the answer, and nothing piles up.
func TestHTTPRelayHandlerReusesConnections(t *testing.T) {
	const sends = 50
	msg := []byte("Subject: x\r\n\r\nbody")

	for _, tc := range []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{name: "204 no body", status: http.StatusNoContent},
		{name: "202 empty body", status: http.StatusAccepted},
		{name: "202 with body", status: http.StatusAccepted, body: `{"status":"queued","id":"0123456789"}`},
		{name: "500 with body", status: http.StatusInternalServerError, body: `{"error":"try again later"}`, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, opened, open := connCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				if tc.body != "" {
					w.Header().Set("Content-Type", "application/json")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})

			before := runtime.NumGoroutine()
			h := &HTTPRelayHandler{HTTPURL: srv.URL, AuthToken: "relay-token"}
			for i := 0; i < sends; i++ {
				err := h.sendToHTTPRelay("a@example.com", "b@example.com", msg)
				if (err != nil) != tc.wantErr {
					t.Fatalf("send %d: sendToHTTPRelay = %v, want error %v", i, err, tc.wantErr)
				}
			}

			if n := opened.Load(); n != 1 {
				t.Errorf("%d sequential sends opened %d connections, want 1 (one reused connection)", sends, n)
			}
			// One kept-alive connection costs a few goroutines (the client's read
			// and write loops, the server's conn goroutine); give connections the
			// client closed a moment to wind down.
			const maxGrowth = 6
			growth := runtime.NumGoroutine() - before
			for deadline := time.Now().Add(2 * time.Second); growth > maxGrowth && time.Now().Before(deadline); {
				time.Sleep(20 * time.Millisecond)
				growth = runtime.NumGoroutine() - before
			}
			if growth > maxGrowth {
				t.Errorf("goroutines grew by %d after %d sends (server-side open connections: %d), want at most %d",
					growth, sends, open.Load(), maxGrowth)
			}
		})
	}
}

// TestHTTPRelayHandlerReusesConnectionsConcurrently: the relay queue worker
// delivers [relay.queue] concurrency messages at once (default 5). The idle pool
// must hold that many connections, or every round closes the surplus and dials it
// again (net/http's default is 2 idle connections per host).
func TestHTTPRelayHandlerReusesConnectionsConcurrently(t *testing.T) {
	const workers, perWorker = 5, 50
	msg := []byte("Subject: x\r\n\r\nbody")

	srv, opened, _ := connCountingServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, `{"status":"queued"}`)
	})

	h := NewRelayHandlerFromConfig("http", "", srv.URL, "relay-token", "test",
		false, false, false, "", "", "", &testLogger{}, CircuitBreakerConfig{})

	var wg sync.WaitGroup
	errs := make(chan error, workers*perWorker)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				if err := h.SendToExternalRelay("a@example.com", "b@example.com", msg); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("SendToExternalRelay: %v", err)
	}

	// Steady state needs one connection per worker. A request that finds no idle
	// connection dials one, and net/http may hand it another request's freed
	// connection first and pool the dialed one, so the warm-up can open up to
	// twice that; after it, connections are only reused.
	if n := opened.Load(); n > 2*workers {
		t.Errorf("%d concurrent workers sending %d messages opened %d connections, want at most %d",
			workers, workers*perWorker, n, 2*workers)
	}
}
