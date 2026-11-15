package imapproxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/resilient"
)

func newStopStartTestServer(t *testing.T, addr string) *Server {
	t.Helper()
	srv, err := New(context.Background(), &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name: "stop-start", Addr: addr, RemoteAddrs: []string{"192.0.2.10:143"}, ConnectTimeout: time.Second,
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
// listener. The proxy must then not serve: Start returns at once instead of
// accepting until the process exits (#823).
func TestStopBeforeStartDoesNotServe(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	srv := newStopStartTestServer(t, addr)
	srv.Stop()
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
		srv.Stop()
		waitStartReturned(t, started)
	}
}
