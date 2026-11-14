package lmtpproxy

import (
	"bufio"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"
)

type shutdownWriteProbe struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
}

func (c *shutdownWriteProbe) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	return c.Conn.Write(p)
}

func TestShutdownNoticeDoesNotHoldSessionMutexDuringWrite(t *testing.T) {
	srv := newImplicitTLSServer(t)
	serverEnd, client := net.Pipe()
	probe := &shutdownWriteProbe{Conn: serverEnd, entered: make(chan struct{})}
	sess := newSession(srv, probe, nil)
	sess.greeted = true
	srv.registerSession(sess)
	done := make(chan struct{})
	go func() { defer close(done); srv.sendGracefulShutdownMessage() }()
	t.Cleanup(func() { client.Close(); <-done })
	select {
	case <-probe.entered:
	case <-time.After(time.Second):
		t.Fatal("the shutdown notice never started")
	}
	if !sess.mu.TryLock() {
		t.Fatal("a blocked notice holds the session mutex needed by cancellation")
	}
	sess.mu.Unlock()
}

func TestShutdownNoticeBoundedForUnresponsiveGreetedClient(t *testing.T) {
	srv := newImplicitTLSServer(t)
	serverEnd, client := net.Pipe()
	t.Cleanup(func() { client.Close() })
	sess := newSession(srv, serverEnd, nil)
	sess.greeted = true
	srv.registerSession(sess)
	done := make(chan struct{})
	go func() { defer close(done); srv.sendGracefulShutdownMessage() }()
	t.Cleanup(func() { client.Close(); <-done })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown waited indefinitely for a greeted client that stopped reading")
	}
}

func TestStopClosesPendingTLSHandshakes(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "direct_Stop"
		if canceled {
			name = "canceled_context"
		}
		t.Run(name, func(t *testing.T) {
			srv := newImplicitTLSServer(t)
			var clients []net.Conn
			for range 3 {
				clients = append(clients, startHandshakingSession(t, srv))
			}
			if canceled {
				srv.cancel()
			}
			done := make(chan struct{})
			go func() { defer close(done); _ = srv.Stop() }()
			t.Cleanup(func() {
				for _, c := range clients {
					c.Close()
				}
				<-done
			})
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("Stop waited for a pending TLS handshake")
			}
			for _, c := range clients {
				assertClosedSilently(t, name, c)
			}
		})
	}
}

func TestStopDoesNotWaitForBackendTLSCloseNotify(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		name := "direct_Stop"
		if canceled {
			name = "canceled_context"
		}
		t.Run(name, func(t *testing.T) {
			srv := newImplicitTLSServer(t)
			serverEnd, client := net.Pipe()
			backendRaw, peerRaw := net.Pipe()
			t.Cleanup(func() { client.Close(); backendRaw.Close(); peerRaw.Close(); srv.cancel() })
			backend := tls.Client(backendRaw, &tls.Config{InsecureSkipVerify: true})
			peer := tls.Server(peerRaw, srv.tlsConfig)
			backend.SetDeadline(time.Now().Add(2 * time.Second))
			peer.SetDeadline(time.Now().Add(2 * time.Second))
			handshaken := make(chan error, 1)
			go func() { handshaken <- peer.Handshake() }()
			if err := backend.Handshake(); err != nil {
				t.Fatal(err)
			}
			if err := <-handshaken; err != nil {
				t.Fatal(err)
			}
			backend.SetDeadline(time.Time{})
			peer.SetDeadline(time.Time{})
			// The backend peer never reads close_notify after this point.
			sess := newSession(srv, serverEnd, nil)
			sess.backendConn = backend
			srv.registerSession(sess)
			srv.sessions.Go(sess.handleConnection)
			if line := readReply(t, bufio.NewReader(client)); len(line) < 4 || line[:4] != "220 " {
				t.Fatalf("unexpected greeting %q", line)
			}
			if canceled {
				srv.cancel()
			}
			done := make(chan struct{})
			go func() { defer close(done); _ = srv.Stop() }()
			t.Cleanup(func() { client.Close(); backendRaw.Close(); peerRaw.Close(); <-done })
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("shutdown waited for an idle TLS backend to read close_notify")
			}
		})
	}
}
