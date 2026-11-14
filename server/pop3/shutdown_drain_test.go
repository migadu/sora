package pop3

import (
	"bufio"
	"errors"
	"net"
	"testing"
	"time"
)

// Shutdown just after a connection was accepted: once Close is draining the
// sessions, the accept loop closes the connection unserved and ends, instead of
// starting a session the drain no longer waits for (#560).
func TestConnectionAcceptedWhileDrainingIsNotServed(t *testing.T) {
	s, addr := newReloadTestServer(t, POP3ServerOptions{CommandTimeout: 10 * time.Second})
	errChan := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		s.Start(errChan)
	}()
	t.Cleanup(s.Close)

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
			t.Fatalf("server did not start: %v", err)
		}
	}

	// The last step of Close: from here on it waits for no new session.
	if !s.sessions.Drain(5 * time.Second) {
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
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("the accept loop kept running after the drain began")
	}
	select {
	case err := <-errChan:
		t.Fatalf("Start reported %v", err)
	default:
	}
}
