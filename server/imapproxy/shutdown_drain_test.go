package imapproxy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/resilient"
)

// Shutdown just after a connection was accepted: once Stop is draining the
// sessions, the accept loop closes the connection unserved, gives back its
// connection-limit slot and ends, instead of starting a session the drain no
// longer waits for (#615).
func TestConnectionAcceptedWhileDrainingIsNotServed(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	srv, err := New(context.Background(), &resilient.ResilientDatabase{}, "localhost", ServerOptions{
		Name: "drain", Addr: addr, RemoteAddrs: []string{"127.0.0.1:1"}, ConnectTimeout: time.Second,
		InsecureAuth: true, MaxConnections: 10,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { srv.Stop() })
	stopped := make(chan error, 1)
	go func() { stopped <- srv.Start() }()

	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := bufio.NewReader(c).ReadString('\n'); err != nil {
				t.Fatalf("greeting: %v", err)
			}
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy did not start: %v", err)
		}
	}

	// What Stop does once the listener is closed: from here on it waits for no
	// new session.
	if !srv.sessions.Drain(5 * time.Second) {
		t.Fatal("the drain did not end after the only session ended")
	}

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err == nil {
		t.Fatalf("a connection accepted while the sessions drain was served: %q", line)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("a connection accepted while the sessions drain was left open")
	}
	select {
	case err := <-stopped:
		if err != nil {
			t.Fatalf("Start returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the accept loop kept running after the drain began")
	}
	if n := srv.limiter.GetStats().TotalConnections; n != 0 {
		t.Errorf("%d connection-limit slot(s) still taken after every connection ended", n)
	}
}
