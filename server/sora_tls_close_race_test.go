package server

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// handshakeEndConn is the TCP connection under a SoraTLSConn. It calls atEnd when a
// successful handshake clears its deadline: the last step before PerformHandshake
// publishes the TLS connection on the SoraConn.
type handshakeEndConn struct {
	net.Conn
	once  sync.Once
	atEnd func()
}

func (c *handshakeEndConn) SetDeadline(t time.Time) error {
	err := c.Conn.SetDeadline(t)
	if t.IsZero() {
		c.once.Do(c.atEnd)
	}
	return err
}

// newHandshakeEndTLSConn returns a SoraTLSConn, as SoraTLSListener accepts it, over a
// loopback connection whose client is handshaking, and that client. atEnd runs on the
// goroutine calling PerformHandshake, at the end of a handshake that succeeded.
func newHandshakeEndTLSConn(t *testing.T, config SoraConnConfig, atEnd func()) (*SoraTLSConn, *tls.Conn) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair("../testdata/sora.crt", "../testdata/sora.key")
	if err != nil {
		t.Fatalf("test certificate: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	raw, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	accepted, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { accepted.Close() })

	client := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
	go func() { _ = client.Handshake() }()

	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	return NewSoraTLSConn(&handshakeEndConn{Conn: accepted, atEnd: atEnd}, serverTLS, config), client
}

// scheduled reports whether c is registered with the global timeout scheduler.
func scheduled(c *SoraConn) bool {
	globalScheduler.mu.Lock()
	defer globalScheduler.mu.Unlock()
	if !globalScheduler.running || len(globalScheduler.shards) == 0 {
		return false
	}
	shard := globalScheduler.shards[globalScheduler.selectShardIndex(c.remoteAddr)]
	shard.mu.RLock()
	defer shard.mu.RUnlock()
	_, ok := shard.conns[c]
	return ok
}

// A server closes a connection from its own goroutine (go-smtp's Server.Close,
// go-imap's, a proxy's shutdown) while the connection's goroutine may still be
// finishing the deferred TLS handshake, which replaces the SoraConn's connection with
// the *tls.Conn (#623). The hook hands the connection to the closer just before that
// replacement and nothing orders the two afterwards, so under -race a Close or Unwrap
// that reads the field unsynchronized is reported whichever runs first.
func TestSoraTLSConnCloseConcurrentWithHandshakeEnd(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(*SoraTLSConn)
	}{
		{"Close", func(c *SoraTLSConn) { _ = c.Close() }},
		// RawConn walks Unwrap from the forced-close timers.
		{"Unwrap", func(c *SoraTLSConn) { _ = RawConn(c).Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ending := make(chan struct{})
			sc, client := newHandshakeEndTLSConn(t, SoraConnConfig{Protocol: "test"}, func() { close(ending) })

			handshake := make(chan error, 1)
			go func() { handshake <- sc.PerformHandshake() }()
			select {
			case <-ending:
			case err := <-handshake:
				t.Fatalf("handshake failed: %v", err)
			}
			tc.call(sc)

			if err := <-handshake; err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("PerformHandshake = %v, want nil or net.ErrClosed", err)
			}
			_ = sc.Close()
			// Whichever came first, the connection is closed: the client reads its end.
			_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := client.Read(make([]byte, 1)); err == nil {
				t.Fatal("client read data, want the connection closed")
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("client read timed out: the connection was left open")
			}
		})
	}
}

// A Close that lands between the end of a successful handshake and the publication of
// its TLS connection has already closed the transport and unregistered the connection
// from the timeout checker. The handshake must then fail, not publish a closed
// connection and register it with the checker, where nothing would ever remove it.
func TestSoraTLSConnHandshakeEndingAfterCloseIsNotPublished(t *testing.T) {
	var sc *SoraTLSConn
	sc, _ = newHandshakeEndTLSConn(t, SoraConnConfig{
		Protocol:             "test",
		IdleTimeout:          time.Hour,
		EnableTimeoutChecker: true,
	}, func() { _ = sc.Close() })
	t.Cleanup(func() { unregisterConn(sc.SoraConn) })

	if err := sc.PerformHandshake(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("PerformHandshake after Close = %v, want net.ErrClosed", err)
	}
	if scheduled(sc.SoraConn) {
		t.Error("closed connection registered with the timeout scheduler")
	}
	if got := sc.CheckedTimeouts(); got != (CheckedTimeouts{}) {
		t.Errorf("closed connection checked with %+v, want none", got)
	}
}
