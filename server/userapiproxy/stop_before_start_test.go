package userapiproxy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/migadu/sora/pkg/resilient"
)

const stopStartTestSecret = "0123456789abcdef0123456789abcdef"

func newStopStartTestServer(t *testing.T, addr string, remoteAddrs ...string) *Server {
	t.Helper()
	if len(remoteAddrs) == 0 {
		remoteAddrs = []string{"192.0.2.10:8081"}
	}
	srv, err := New(context.Background(), &resilient.ResilientDatabase{}, ServerOptions{
		Name:           "stop-start",
		Addr:           addr,
		RemoteAddrs:    remoteAddrs,
		JWTSecret:      stopStartTestSecret,
		ConnectTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// waitStartReturned fails the test unless Start has returned, without error,
// within a few seconds.
func waitStartReturned(t *testing.T, started <-chan error) {
	t.Helper()
	select {
	case err := <-started:
		if err != nil {
			t.Fatalf("Start returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start still accepting 3s after Stop")
	}
}

// cmd/sora runs Stop from a context watcher that races Start, so a shutdown
// during start-up can stop the proxy before (or while) Start creates its
// listener. The proxy must then not bind or serve, and Start must return nil
// like the other proxies rather than http.ErrServerClosed.
func TestStopBeforeStartDoesNotServe(t *testing.T) {
	// Hold a port open to prove Start after Stop never calls net.Listen at all
	// (binding it would fail with EADDRINUSE).
	held, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	srvHeld := newStopStartTestServer(t, held.Addr().String())
	if err := srvHeld.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	startedHeld := make(chan error, 1)
	go func() { startedHeld <- srvHeld.Start() }()
	waitStartReturned(t, startedHeld)

	// Also verify on a free address that nothing is left listening.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	srv := newStopStartTestServer(t, addr)
	if err := srv.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	started := make(chan error, 1)
	go func() { started <- srv.Start() }()
	waitStartReturned(t, started)

	if c, err := net.Dial("tcp", addr); err == nil {
		c.Close()
		t.Fatalf("%s accepts connections after a Stop that came before Start", addr)
	}
}

// Stop at varying points of Start: before, while and after it creates the
// listener.
func TestStopRacingStartEndsStart(t *testing.T) {
	for i := 0; i < 20; i++ {
		srv := newStopStartTestServer(t, "127.0.0.1:0")
		started := make(chan error, 1)
		go func() { started <- srv.Start() }()
		time.Sleep(time.Duration(i) * 100 * time.Microsecond)
		if err := srv.Stop(); err != nil {
			t.Fatalf("Stop: %v", err)
		}
		waitStartReturned(t, started)
	}
}

// Stop must wait for httpServer.Shutdown to finish draining in-flight HTTP
// requests before returning (previously s.wg was never incremented, so Stop
// returned immediately while requests were still running).
func TestStopWaitsForInFlightHandler(t *testing.T) {
	inFlight := make(chan struct{})
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(inFlight)
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	srv := newStopStartTestServer(t, addr, backend.Listener.Addr().String())
	started := make(chan error, 1)
	go func() { started <- srv.Start() }()

	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy did not listen on %s", addr)
		}
	}

	claims := JWTClaims{
		Email:     "user@example.com",
		AccountID: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Subject:   "user@example.com",
		},
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(stopStartTestSecret))
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}

	reqDone := make(chan error, 1)
	go func() {
		req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/user/mailboxes", nil)
		if err != nil {
			reqDone <- err
			return
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			reqDone <- err
			return
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("proxied status = %d, want 200", resp.StatusCode)
		}
		reqDone <- nil
	}()

	select {
	case <-inFlight:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not reach backend")
	}

	stopDone := make(chan error, 1)
	go func() { stopDone <- srv.Stop() }()

	select {
	case err := <-stopDone:
		close(release)
		t.Fatalf("Stop returned (%v) while an HTTP request was still in flight", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)

	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("Stop: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not return after in-flight request completed")
	}

	select {
	case err := <-reqDone:
		if err != nil {
			t.Fatalf("in-flight request failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client did not receive response")
	}

	waitStartReturned(t, started)
}
