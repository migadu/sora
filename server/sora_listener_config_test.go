package server

import (
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// A listener built with a config function asks it at every accept: a config reload
// reaches the connections accepted after it, and those already accepted keep theirs.
// What a connection got is what its timeout checker enforces (CheckedTimeouts), on a
// TLS listener once the deferred handshake has registered it.
func TestSoraListenerFunc_ConfigPerAccept(t *testing.T) {
	cert, err := tls.LoadX509KeyPair("../testdata/sora.crt", "../testdata/sora.key")
	if err != nil {
		t.Fatalf("test certificate: %v", err)
	}
	serverTLS := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	var idle atomic.Int64
	config := func() SoraConnConfig {
		return SoraConnConfig{Protocol: "test", IdleTimeout: time.Duration(idle.Load()), EnableTimeoutChecker: true}
	}

	for _, tc := range []struct {
		name string
		tls  bool
		wrap func(net.Listener) net.Listener
	}{
		{"plain", false, func(l net.Listener) net.Listener { return NewSoraListenerFunc(l, config) }},
		{"tls", true, func(l net.Listener) net.Listener { return NewSoraTLSListenerFunc(l, serverTLS, config) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idle.Store(int64(time.Minute))
			base, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			l := tc.wrap(base)
			defer l.Close()

			accept := func() net.Conn {
				t.Helper()
				c, err := net.Dial("tcp", base.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { c.Close() })
				if tc.tls {
					go func() { _ = tls.Client(c, &tls.Config{InsecureSkipVerify: true}).Handshake() }()
				}
				conn, err := l.Accept()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { conn.Close() })
				if _, err := PerformDeferredTLSHandshake(conn); err != nil {
					t.Fatalf("handshake: %v", err)
				}
				return conn
			}

			before := accept()
			idle.Store(int64(2 * time.Minute))
			after := accept()
			for _, c := range []struct {
				which string
				conn  net.Conn
				want  time.Duration
			}{{"before", before, time.Minute}, {"after", after, 2 * time.Minute}} {
				got, ok := ConnCheckedTimeouts(c.conn)
				if !ok || got.Idle != c.want {
					t.Errorf("connection accepted %s the change: checked %+v (found %v), want idle %v", c.which, got, ok, c.want)
				}
			}
			// STARTTLS puts a *tls.Conn on top of the SoraConn; it is still found.
			if got, ok := ConnCheckedTimeouts(tls.Server(after, serverTLS)); !ok || got.Idle != 2*time.Minute {
				t.Errorf("under a *tls.Conn: checked %+v (found %v), want idle 2m", got, ok)
			}
		})
	}
}
