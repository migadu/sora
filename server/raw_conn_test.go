package server

import (
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
)

// rawConnLayer is a walkable net.Conn layer for these tests: Unwrap() answers
// whatever the test chose (nil included), and Close is counted on the layer
// itself and not forwarded, so a test can tell which layers a forced close hit.
type rawConnLayer struct {
	net.Conn
	inner  net.Conn
	closes atomic.Int32
}

func (l *rawConnLayer) Unwrap() net.Conn { return l.inner }
func (l *rawConnLayer) Close() error     { l.closes.Add(1); return nil }

// rawConnLeaf is a net.Conn with neither Unwrap() nor NetConn(), the walk's
// natural end, that counts its Close calls without forwarding them.
type rawConnLeaf struct {
	net.Conn
	closes atomic.Int32
}

func (l *rawConnLeaf) Close() error { l.closes.Add(1); return nil }

func TestRawConn(t *testing.T) {
	pipe, peer := net.Pipe()
	defer pipe.Close()
	defer peer.Close()
	// NetConn() is reachable on a tls.Conn that never handshook.
	tlsConn := tls.Client(pipe, &tls.Config{InsecureSkipVerify: true})
	once := &rawConnLayer{Conn: pipe, inner: pipe}
	twice := &rawConnLayer{Conn: once, inner: once}
	// tls.Conn.NetConn() can be a wrapper (bufferedConn after the plaintext
	// probe peeked bytes); the walk must continue through it.
	tlsOverWrapper := tls.Client(once, &tls.Config{InsecureSkipVerify: true})
	nilBelow := &rawConnLayer{Conn: pipe, inner: nil}
	nilDeeper := &rawConnLayer{Conn: nilBelow, inner: nilBelow}

	tests := []struct {
		name string
		conn net.Conn
		want net.Conn
	}{
		{"nil", nil, nil},
		{"plain conn", pipe, pipe},
		{"tls.Conn", tlsConn, pipe},
		{"one Unwrap layer", once, pipe},
		{"two Unwrap layers", twice, pipe},
		{"tls.Conn over an Unwrap layer", tlsOverWrapper, pipe},
		{"Unwrap yields nil", nilBelow, nilBelow},
		{"Unwrap yields nil below a layer", nilDeeper, nilBelow},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RawConn(tc.conn); got != tc.want {
				t.Fatalf("RawConn() = %T (%p), want %T (%p)", got, got, tc.want, tc.want)
			}
		})
	}
}

// closeTimeoutTransport closes only the innermost socket: the wrappers' own
// Close runs afterwards from closeForTimeout (c.Close), and a nil transport is
// nothing to close rather than a crash in the timer goroutine.
func TestCloseTimeoutTransport(t *testing.T) {
	socket := &rawConnLeaf{}
	outer := &rawConnLayer{Conn: socket, inner: socket}
	closeTimeoutTransport(outer)
	if got := socket.closes.Load(); got != 1 {
		t.Errorf("innermost socket Close calls = %d, want 1", got)
	}
	if got := outer.closes.Load(); got != 0 {
		t.Errorf("outer wrapper Close calls = %d, want 0 (closeForTimeout's deferred c.Close does that)", got)
	}

	bare := &rawConnLeaf{}
	closeTimeoutTransport(bare)
	if got := bare.closes.Load(); got != 1 {
		t.Errorf("bare socket Close calls = %d, want 1", got)
	}

	closeTimeoutTransport(nil)
}
