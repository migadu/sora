package lmtpproxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type regreetingBackendCloseWrite struct {
	net.Conn
	armed   atomic.Bool
	once    sync.Once
	entered chan struct{}
}

func (c *regreetingBackendCloseWrite) Write(p []byte) (int, error) {
	if c.armed.Load() {
		c.once.Do(func() { close(c.entered) })
	}
	return c.Conn.Write(p)
}

// Re-greeting drops a backend held from an earlier transaction. A peer that
// stops reading TLS must not hold the session mutex and defeat Stop's raw
// transport abort while the drop waits for close_notify.
func TestRegreetingTLSBackendDoesNotBlockStop(t *testing.T) {
	srv := newImplicitTLSServer(t)
	backendRaw, peerRaw := net.Pipe()
	wrapped := &regreetingBackendCloseWrite{Conn: backendRaw, entered: make(chan struct{})}
	backend := tls.Client(wrapped, &tls.Config{InsecureSkipVerify: true})
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
	wrapped.armed.Store(true)
	// From here the TLS backend peer does not read close_notify.
	serverEnd, client := net.Pipe()
	t.Cleanup(func() { client.Close(); backendRaw.Close(); peerRaw.Close(); srv.cancel() })
	sess := newSession(srv, serverEnd, nil)
	srv.sessions.Go(sess.handleConnection)
	client.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(client)
	if line := readReply(t, r); !strings.HasPrefix(line, "220 ") {
		t.Fatal(line)
	}
	io.WriteString(client, "LHLO first.example\r\n")
	if line := readReply(t, r); !strings.HasPrefix(line, "250 ") {
		t.Fatal(line)
	}
	// Model the healthy TLS backend held from an earlier transaction. The
	// command loop is waiting for input; the next pipe write publishes this.
	sess.mu.Lock()
	sess.backendConn = backend
	sess.mu.Unlock()
	io.WriteString(client, "LHLO second.example\r\n")
	replied := make(chan error, 1)
	go func() {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				replied <- err
				return
			}
			if len(line) < 4 || line[3] != '-' {
				if !strings.HasPrefix(line, "250 ") {
					err = fmt.Errorf("LHLO: %q", line)
				}
				replied <- err
				return
			}
		}
	}()
	select {
	case <-wrapped.entered: // the backend close has started
	case err := <-replied:
		if err != nil {
			t.Fatal(err)
		} // the LHLO completed before shutdown
	case <-time.After(2 * time.Second):
		t.Fatal("LHLO neither replied nor closed backend")
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Stop() }()
	t.Cleanup(func() { client.Close(); backendRaw.Close(); peerRaw.Close(); <-done })
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Error("Stop waited for LHLO's backend TLS close_notify while session mutex was held")
	}
}
