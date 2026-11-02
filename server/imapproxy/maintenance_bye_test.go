package imapproxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

const maintenanceBye = "* BYE [UNAVAILABLE] Server in maintenance, please reconnect\r\n"

// proxiedSession is a session in proxy mode: the backend-to-client copy runs, the test
// writes as the backend and reads everything the client receives.
type proxiedSession struct {
	s       *Session
	backend net.Conn // the backend's end

	mu       sync.Mutex
	received bytes.Buffer
	closed   chan struct{} // the client's connection ended
}

func newProxiedSession(t *testing.T) *proxiedSession {
	t.Helper()
	backendEnd, backendProxy := net.Pipe()
	clientProxy, clientEnd := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv := &Server{name: "test-imap-proxy", ctx: ctx, activeSessions: map[*Session]struct{}{}}
	s := &Session{server: srv, ctx: ctx, clientConn: clientProxy, backendConn: backendProxy, backendReader: bufio.NewReader(backendProxy)}
	srv.activeSessions[s] = struct{}{}
	p := &proxiedSession{s: s, backend: backendEnd, closed: make(chan struct{})}

	go func() { _, _ = s.copyBufferedReaderToConn(clientProxy, s.backendReader) }()
	go func() {
		defer close(p.closed)
		buf := make([]byte, 4096)
		for {
			n, err := clientEnd.Read(buf)
			p.mu.Lock()
			p.received.Write(buf[:n])
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { backendEnd.Close(); clientEnd.Close() })
	return p
}

// send writes as the backend and waits until the client has it all.
func (p *proxiedSession) send(t *testing.T, data string) {
	t.Helper()
	want := p.text() + data
	if _, err := io.WriteString(p.backend, data); err != nil {
		t.Fatalf("backend write: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !strings.HasPrefix(p.text(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("client did not receive %q; has %q", data, p.text())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// sendAsync writes as the backend without waiting: after a BYE nothing is forwarded, so
// the write may never be read.
func (p *proxiedSession) sendAsync(data string) {
	go func() { _, _ = io.WriteString(p.backend, data) }()
}

func (p *proxiedSession) text() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.received.String()
}

// untilClosed returns everything the client received once its connection ended.
func (p *proxiedSession) untilClosed(t *testing.T) string {
	t.Helper()
	select {
	case <-p.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("client connection still open")
	}
	return p.text()
}

// A BYE never lands inside a response: with a literal under way it waits for the end of
// the response, and nothing from the backend follows it.
func TestMaintenanceBye_WaitsForTheEndOfTheResponse(t *testing.T) {
	p := newProxiedSession(t)
	p.send(t, "* 1 FETCH (BODY[] {20}\r\n0123456789")

	p.s.closeForMaintenance()
	time.Sleep(50 * time.Millisecond)
	p.send(t, "abcdefghij FLAGS (\\Seen))\r\n")
	p.sendAsync("* 2 FETCH (FLAGS ())\r\n")

	got := p.untilClosed(t)
	want := "* 1 FETCH (BODY[] {20}\r\n0123456789abcdefghij FLAGS (\\Seen))\r\n" + maintenanceBye
	if got != want {
		t.Fatalf("client received\n%q\nwant\n%q", got, want)
	}
}

// Between responses (an IDLE session, say) the BYE goes out at once.
func TestMaintenanceBye_AtOnceBetweenResponses(t *testing.T) {
	p := newProxiedSession(t)
	p.send(t, "+ idling\r\n")

	start := time.Now()
	p.s.closeForMaintenance()
	deadline := time.Now().Add(maintenanceByeDelay / 2)
	for !strings.HasSuffix(p.text(), maintenanceBye) {
		if time.Now().After(deadline) {
			t.Fatalf("no BYE within %v of an idle session's close; client has %q", time.Since(start), p.text())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := p.untilClosed(t); got != "+ idling\r\n"+maintenanceBye {
		t.Fatalf("client received %q", got)
	}
}

// A response that does not end before the session closes gets no BYE: the client is cut
// off inside a literal and discards it, where a BYE could have completed it.
func TestMaintenanceBye_NoneInsideAResponseThatDoesNotEnd(t *testing.T) {
	p := newProxiedSession(t)
	p.send(t, "* 1 FETCH (BODY[] {64}\r\n0123456789")

	p.s.closeForMaintenance()
	if got := p.untilClosed(t); strings.Contains(got, "BYE") {
		t.Fatalf("BYE written inside an unfinished literal: %q", got)
	}
}

// A session is closed for maintenance once: a later sweep neither lists it again nor
// writes a second BYE.
func TestCloseForMaintenance_OnlyOnce(t *testing.T) {
	p := newProxiedSession(t)
	p.send(t, "* OK\r\n")

	p.s.closeForMaintenance()
	if targets := p.s.server.MaintenanceTargets(); len(targets) != 0 {
		t.Fatalf("a session already closing is still a drain target: %+v", targets)
	}
	p.s.closeForMaintenance()
	if got := p.untilClosed(t); strings.Count(got, "BYE") != 1 {
		t.Fatalf("client received %q, want exactly one BYE", got)
	}
}

// The shutdown BYE follows the same rule as the maintenance one.
func TestShutdownBye_WaitsForTheEndOfTheResponse(t *testing.T) {
	p := newProxiedSession(t)
	p.send(t, "* 1 FETCH (BODY[] {20}\r\n0123456789")

	done := make(chan struct{})
	go func() { defer close(done); p.s.server.sendGracefulShutdownBye() }()
	time.Sleep(50 * time.Millisecond)
	p.send(t, "abcdefghij)\r\n")
	<-done

	got := p.untilClosed(t)
	if !strings.HasPrefix(got, "* 1 FETCH (BODY[] {20}\r\n0123456789abcdefghij)\r\n") {
		t.Fatalf("shutdown BYE broke into the response: %q", got)
	}
	if !strings.HasSuffix(got, "* BYE Server shutting down, please reconnect\r\n") {
		t.Fatalf("no shutdown BYE after the response: %q", got)
	}
}
