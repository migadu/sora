package server

import (
	"crypto/tls"
	"net"
)

// RawConn returns the innermost transport under conn: the socket beneath every
// layer Sora stacks on it (SoraConn, PROXY-protocol and limiter wrappers,
// bufferedConn, *tls.Conn). It follows a *tls.Conn through NetConn(), which
// never triggers a handshake, and any other layer through Unwrap() net.Conn,
// and stops at the first layer that offers neither. A step that yields nil ends
// the walk at the last non-nil layer, so the result is nil only when conn is:
// the forced-close paths call this from a timer goroutine, where a nil inner
// connection must be nothing to close rather than a crash.
//
// Closing what it returns bypasses TLS close_notify and every wrapper's
// bookkeeping. That is what a forced close wants (the outer Close can wait on
// the very write the deadline must interrupt); the caller closes the outer conn
// itself when nothing else will.
func RawConn(conn net.Conn) net.Conn {
	if conn == nil {
		return nil
	}
	for {
		var inner net.Conn
		switch c := conn.(type) {
		case *tls.Conn:
			inner = c.NetConn()
		case interface{ Unwrap() net.Conn }:
			inner = c.Unwrap()
		default:
			return conn
		}
		if inner == nil {
			return conn
		}
		conn = inner
	}
}
