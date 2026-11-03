package imapproxy

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const maintenanceBye = "* BYE [UNAVAILABLE] Server in maintenance, please reconnect\r\n"

// proxiedSession is a session in proxy mode, running the proxy's own copy loop
// (startProxy). The test plays the backend (over TCP, so a half-close shows) and reads
// everything the client receives.
type proxiedSession struct {
	s       *Session
	backend net.Conn // the backend's end
	client  net.Conn // the client's end

	mu          sync.Mutex
	received    bytes.Buffer // what the client got
	fromClient  bytes.Buffer // what the backend got
	clientEnded chan struct{}
	backendEOF  atomic.Bool // the backend read EOF: nothing more will reach it
}

func newProxiedSession(t *testing.T) *proxiedSession {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	backendProxy, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	backendEnd, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	ln.Close()
	clientProxy, clientEnd := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv := &Server{name: "test-imap-proxy", ctx: ctx, activeSessions: map[*Session]struct{}{}}
	s := &Session{
		server: srv, ctx: ctx,
		clientConn: clientProxy, clientReader: bufio.NewReader(clientProxy),
		backendConn: backendProxy, backendReader: bufio.NewReader(backendProxy),
	}
	srv.activeSessions[s] = struct{}{}
	p := &proxiedSession{s: s, backend: backendEnd, client: clientEnd, clientEnded: make(chan struct{})}

	go s.startProxy()
	go func() {
		defer close(p.clientEnded)
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
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := backendEnd.Read(buf)
			p.mu.Lock()
			p.fromClient.Write(buf[:n])
			p.mu.Unlock()
			if err != nil {
				p.backendEOF.Store(true)
				return
			}
		}
	}()
	t.Cleanup(func() { backendEnd.Close(); clientEnd.Close() })

	// Proxying from here on (the drain only targets sessions past their login).
	waitFor(t, func() bool { return len(srv.MaintenanceTargets()) == 1 }, "the session to be proxying")
	return p
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// send writes as the backend and waits until the client has it all.
func (p *proxiedSession) send(t *testing.T, data string) {
	t.Helper()
	want := p.text() + data
	if _, err := io.WriteString(p.backend, data); err != nil {
		t.Fatalf("backend write: %v", err)
	}
	waitFor(t, func() bool { return strings.HasPrefix(p.text(), want) }, "the client to receive "+data)
}

// command writes as the client and waits until the backend has it.
func (p *proxiedSession) command(t *testing.T, data string) {
	t.Helper()
	go func() { _, _ = io.WriteString(p.client, data) }()
	waitFor(t, func() bool { return strings.Contains(p.backendGot(), data) }, "the backend to receive "+data)
}

func (p *proxiedSession) text() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.received.String()
}

func (p *proxiedSession) backendGot() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fromClient.String()
}

// untilClosed returns everything the client received once its connection ended.
func (p *proxiedSession) untilClosed(t *testing.T, within time.Duration) string {
	t.Helper()
	select {
	case <-p.clientEnded:
	case <-time.After(within):
		t.Fatalf("client connection still open after %v; received %q", within, p.text())
	}
	return p.text()
}

// withCloseGrace sets how long a session closed for maintenance may take to end.
func withCloseGrace(t *testing.T, d time.Duration) {
	t.Helper()
	saved := maintenanceCloseGrace
	maintenanceCloseGrace = d
	t.Cleanup(func() { maintenanceCloseGrace = saved })
}

// A BYE never lands inside a response: with a literal under way it waits for the end of
// the response. Complete responses still follow it until the backend closes.
func TestMaintenanceBye_WaitsForTheEndOfTheResponse(t *testing.T) {
	withCloseGrace(t, 5*time.Second)
	p := newProxiedSession(t)
	p.send(t, "* 1 FETCH (BODY[] {20}\r\n0123456789")

	p.s.closeForMaintenance()
	time.Sleep(50 * time.Millisecond)
	if _, err := io.WriteString(p.backend, "abcdefghij FLAGS (\\Seen))\r\n* 2 FETCH (FLAGS ())\r\n"); err != nil {
		t.Fatalf("backend write: %v", err)
	}
	p.backend.Close()

	got := p.untilClosed(t, 2*time.Second)
	want := "* 1 FETCH (BODY[] {20}\r\n0123456789abcdefghij FLAGS (\\Seen))\r\n" + maintenanceBye + "* 2 FETCH (FLAGS ())\r\n"
	if got != want {
		t.Fatalf("client received\n%q\nwant\n%q", got, want)
	}
}

// Between responses (an IDLE session, say) the BYE goes out at once.
func TestMaintenanceBye_AtOnceBetweenResponses(t *testing.T) {
	withCloseGrace(t, 5*time.Second)
	p := newProxiedSession(t)
	p.send(t, "+ idling\r\n")

	p.s.closeForMaintenance()
	waitFor(t, func() bool { return strings.HasSuffix(p.text(), maintenanceBye) }, "the BYE")
	p.backend.Close()
	if got := p.untilClosed(t, 2*time.Second); got != "+ idling\r\n"+maintenanceBye {
		t.Fatalf("client received %q", got)
	}
}

// A command the backend already has gets its reply although the BYE went out first: a
// client that saw no tagged OK for an APPEND it sent would send it again after
// reconnecting, and the mail would be there twice. Nothing the client sends after the BYE
// reaches the backend, and the session ends as soon as the backend is done.
func TestMaintenanceBye_InFlightCommandStillGetsItsReply(t *testing.T) {
	withCloseGrace(t, 10*time.Second)
	p := newProxiedSession(t)
	p.command(t, "a5 APPEND INBOX {3+}\r\nabc\r\n")

	p.s.closeForMaintenance()
	waitFor(t, func() bool { return strings.HasSuffix(p.text(), maintenanceBye) }, "the BYE")
	waitFor(t, p.backendEOF.Load, "the backend to see the end of client input")
	go func() { _, _ = io.WriteString(p.client, "a6 NOOP\r\n") }()

	p.send(t, "a5 OK [APPENDUID 1 7] APPEND completed\r\n")
	p.backend.Close()
	got := p.untilClosed(t, 2*time.Second)
	if got != maintenanceBye+"a5 OK [APPENDUID 1 7] APPEND completed\r\n" {
		t.Fatalf("client received %q, want the BYE and then the APPEND's tagged reply", got)
	}
	if strings.Contains(p.backendGot(), "a6 NOOP") {
		t.Fatalf("a command sent after the BYE reached the backend: %q", p.backendGot())
	}
}

// A response that does not end before the session has to close gets no BYE: the client,
// cut off inside a literal, discards it, where a BYE could have been read as part of it.
func TestMaintenanceBye_NoneInsideAResponseThatDoesNotEnd(t *testing.T) {
	withCloseGrace(t, 300*time.Millisecond)
	p := newProxiedSession(t)
	p.send(t, "* 1 FETCH (BODY[] {64}\r\n0123456789")

	p.s.closeForMaintenance()
	if got := p.untilClosed(t, 2*time.Second); strings.Contains(got, "BYE") {
		t.Fatalf("BYE written inside an unfinished literal: %q", got)
	}
}

// A session is closed for maintenance once: a later sweep neither lists it again nor
// writes a second BYE.
func TestCloseForMaintenance_OnlyOnce(t *testing.T) {
	withCloseGrace(t, 5*time.Second)
	p := newProxiedSession(t)
	p.send(t, "* OK\r\n")

	p.s.closeForMaintenance()
	if targets := p.s.server.MaintenanceTargets(); len(targets) != 0 {
		t.Fatalf("a session already closing is still a drain target: %+v", targets)
	}
	p.s.closeForMaintenance()
	waitFor(t, func() bool { return strings.Contains(p.text(), "BYE") }, "the BYE")
	p.backend.Close()
	if got := p.untilClosed(t, 2*time.Second); strings.Count(got, "BYE") != 1 {
		t.Fatalf("client received %q, want exactly one BYE", got)
	}
}

// A session still logging in (its backend dialed, the login reply not yet sent) is not a
// drain target: a BYE could reach the client before the tagged reply to its LOGIN. The
// next sweep finds it once it proxies.
func TestMaintenanceTargets_NotBeforeProxying(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	backendConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer backendConn.Close()

	session := &Session{backendConn: backendConn, serverAddr: ln.Addr().String()}
	s := &Server{activeSessions: map[*Session]struct{}{session: {}}}
	if targets := s.MaintenanceTargets(); len(targets) != 0 {
		t.Fatalf("a session still logging in is a drain target: %+v", targets)
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

	got := p.untilClosed(t, 2*time.Second)
	if !strings.HasPrefix(got, "* 1 FETCH (BODY[] {20}\r\n0123456789abcdefghij)\r\n") {
		t.Fatalf("shutdown BYE broke into the response: %q", got)
	}
	if !strings.HasSuffix(got, "* BYE Server shutting down, please reconnect\r\n") {
		t.Fatalf("no shutdown BYE after the response: %q", got)
	}
}
