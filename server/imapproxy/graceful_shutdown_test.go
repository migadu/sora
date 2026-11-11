package imapproxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// eventLog records operations across multiple connections in a global order
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (e *eventLog) record(event string) {
	e.mu.Lock()
	e.events = append(e.events, event)
	e.mu.Unlock()
}

func (e *eventLog) getEvents() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make([]string, len(e.events))
	copy(result, e.events)
	return result
}

// trackedConn wraps net.Conn and records events to a shared log
type trackedConn struct {
	net.Conn
	name string
	log  *eventLog
}

func (c *trackedConn) Write(b []byte) (int, error) {
	data := string(b)
	if strings.Contains(data, "BYE") {
		c.log.record(c.name + ":write_bye")
	} else if strings.Contains(data, "LOGOUT") {
		c.log.record(c.name + ":write_logout")
	} else {
		c.log.record(c.name + ":write_data")
	}
	return c.Conn.Write(b)
}

func (c *trackedConn) Close() error {
	c.log.record(c.name + ":close")
	return c.Conn.Close()
}

// TestSendGracefulShutdownBye_ByeWrittenBeforeClose verifies the shutdown
// sequence: BYE is written to client, then both connections are closed.
// The gracefulShutdown flag prevents the copy goroutine from closing clientConn
// before the BYE message is delivered.
func TestSendGracefulShutdownBye_ByeWrittenBeforeClose(t *testing.T) {
	log := &eventLog{}

	// Create the actual pipe ends
	clientLocal, clientProxyRaw := net.Pipe()
	backendProxyRaw, backendLocal := net.Pipe()

	// Wrap with tracking using shared event log
	clientProxy := &trackedConn{Conn: clientProxyRaw, name: "client", log: log}
	backendProxy := &trackedConn{Conn: backendProxyRaw, name: "backend", log: log}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := &Server{
		name:           "test-imap-proxy",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
	}

	sessionCtx, sessionCancel := context.WithCancel(ctx)
	session := &Session{
		server:        srv,
		clientConn:    clientProxy,
		listenerConn:  clientProxy,
		backendConn:   backendProxy,
		backendReader: bufio.NewReader(backendProxy),
		clientWriter:  bufio.NewWriter(clientProxy),
		backendWriter: bufio.NewWriter(backendProxy),
		ctx:           sessionCtx,
		cancel:        sessionCancel,
		username:      "test@example.com",
		startTime:     time.Now(),
	}
	srv.addSession(session)

	// Drain client side to prevent write blocking
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		buf := make([]byte, 4096)
		for {
			_, err := clientLocal.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Drain backend side (for LOGOUT write) to prevent write blocking
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		buf := make([]byte, 4096)
		for {
			_, err := backendLocal.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Trigger graceful shutdown
	srv.sendGracefulShutdownBye()

	events := log.getEvents()
	t.Logf("Event ordering: %v", events)

	// Find the indices of key events
	backendCloseIdx := -1
	clientByeIdx := -1
	for i, e := range events {
		if e == "backend:close" && backendCloseIdx == -1 {
			backendCloseIdx = i
		}
		if e == "client:write_bye" && clientByeIdx == -1 {
			clientByeIdx = i
		}
	}

	if backendCloseIdx < 0 {
		t.Fatal("Backend close event not found in event log")
	}
	if clientByeIdx < 0 {
		t.Fatal("Client BYE write event not found in event log")
	}

	// CRITICAL ASSERTION: BYE must be written to client BEFORE connections are closed.
	// The gracefulShutdown flag prevents the copy goroutine from closing clientConn,
	// so the BYE message is safely delivered before shutdown completes.
	if clientByeIdx > backendCloseIdx {
		t.Errorf("BYE written to client (event %d) AFTER backend closed (event %d).\n"+
			"Events: %v\n"+
			"BYE should be sent to client before connections are torn down.",
			clientByeIdx, backendCloseIdx, events)
	}

	// Clean up
	cancel()
	clientLocal.Close()
	backendLocal.Close()
	<-clientDone
	<-backendDone
}

// TestSendGracefulShutdownBye_CleanByeDuringActiveTransfer verifies that the BYE
// message arrives as a complete, unbroken line even when data is actively flowing
// from the backend through the proxy to the client.
func TestSendGracefulShutdownBye_CleanByeDuringActiveTransfer(t *testing.T) {
	// clientLocal is what the "client application" reads from
	// clientProxy is what the proxy writes to (the proxy's clientConn)
	clientLocal, clientProxy := net.Pipe()

	// backendProxy is what the proxy reads from (the proxy's backendConn)
	// backendLocal is what the "backend server" writes to
	backendProxy, backendLocal := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := &Server{
		name:           "test-imap-proxy",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
	}

	sessionCtx, sessionCancel := context.WithCancel(ctx)
	session := &Session{
		server:        srv,
		clientConn:    clientProxy,
		listenerConn:  clientProxy,
		backendConn:   backendProxy,
		backendReader: bufio.NewReader(backendProxy),
		clientWriter:  bufio.NewWriter(clientProxy),
		ctx:           sessionCtx,
		cancel:        sessionCancel,
		username:      "test@example.com",
		startTime:     time.Now(),
	}
	srv.addSession(session)

	// Start proxy in a goroutine (bidirectional copy)
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		session.startProxy()
	}()

	// Collect all data received by the client side
	var received []byte
	var receivedMu sync.Mutex
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		buf := make([]byte, 4096)
		for {
			n, err := clientLocal.Read(buf)
			if n > 0 {
				receivedMu.Lock()
				received = append(received, buf[:n]...)
				receivedMu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	// Backend sends continuous IMAP-like data to simulate an active transfer
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		for i := 0; ; i++ {
			_, err := backendLocal.Write([]byte(fmt.Sprintf("* %d EXISTS\r\n", i)))
			if err != nil {
				return
			}
		}
	}()

	// Let data flow for a bit
	time.Sleep(50 * time.Millisecond)

	// Trigger graceful shutdown — this is what we're testing
	srv.sendGracefulShutdownBye()

	// Clean up
	cancel()
	clientLocal.Close()
	backendLocal.Close()

	// Wait for goroutines
	select {
	case <-proxyDone:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not exit within timeout")
	}
	<-clientDone
	<-backendDone

	// Verify BYE appears as a complete, unbroken line
	receivedMu.Lock()
	data := string(received)
	receivedMu.Unlock()

	byeMsg := "* BYE Server shutting down, please reconnect"

	if !strings.Contains(data, byeMsg) {
		t.Fatalf("BYE message not found in received data. Last 200 bytes:\n%s",
			data[max(0, len(data)-200):])
	}

	// Verify the BYE appears as a complete line (not interleaved with other data)
	lines := strings.Split(data, "\r\n")
	byeClean := false
	for _, line := range lines {
		if line == byeMsg {
			byeClean = true
			break
		}
	}
	if !byeClean {
		// Find the line containing BYE to show what it got interleaved with
		for _, line := range lines {
			if strings.Contains(line, "BYE") {
				t.Errorf("BYE message was interleaved with other data: %q", line)
				return
			}
		}
		t.Errorf("BYE message not found as a complete line in received data")
	}
}

// TestSendGracefulShutdownBye_IdleSession verifies BYE works for idle sessions
// (the common case where IMAP client is in IDLE mode with no data flowing)
func TestSendGracefulShutdownBye_IdleSession(t *testing.T) {
	clientLocal, clientProxy := net.Pipe()
	backendProxy, backendLocal := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := &Server{
		name:           "test-imap-proxy",
		ctx:            ctx,
		cancel:         cancel,
		activeSessions: make(map[*Session]struct{}),
	}

	sessionCtx, sessionCancel := context.WithCancel(ctx)
	session := &Session{
		server:        srv,
		clientConn:    clientProxy,
		listenerConn:  clientProxy,
		backendConn:   backendProxy,
		backendReader: bufio.NewReader(backendProxy),
		clientWriter:  bufio.NewWriter(clientProxy),
		ctx:           sessionCtx,
		cancel:        sessionCancel,
		username:      "idle@example.com",
		startTime:     time.Now(),
	}
	srv.addSession(session)

	// Start proxy (no data flowing — idle session)
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		session.startProxy()
	}()

	// Let proxy goroutines start and block on reads
	time.Sleep(50 * time.Millisecond)

	// Collect client data
	var received []byte
	var receivedMu sync.Mutex
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		buf := make([]byte, 4096)
		for {
			n, err := clientLocal.Read(buf)
			if n > 0 {
				receivedMu.Lock()
				received = append(received, buf[:n]...)
				receivedMu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	// Trigger graceful shutdown on idle session
	srv.sendGracefulShutdownBye()

	// Clean up
	cancel()
	clientLocal.Close()
	backendLocal.Close()
	<-proxyDone
	<-clientDone

	// Verify client received a clean BYE as the only message
	receivedMu.Lock()
	data := string(received)
	receivedMu.Unlock()

	expected := "* BYE Server shutting down, please reconnect\r\n"
	if data != expected {
		t.Errorf("Expected only BYE message, got: %q", data)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
