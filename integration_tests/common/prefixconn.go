package common

import "net"

// PrefixConn prepends prefix to the first Write, so a PROXY protocol header
// and the TLS ClientHello leave in a single Write (one TCP segment on
// loopback). This forces the server's PROXY reader to buffer ClientHello
// bytes along with the header — the TLS handshake must read through the
// PROXY conn to see them, which is exactly the listener wrapping-order
// property under test (see docs/proxy-protocol-tls-composition.md).
type PrefixConn struct {
	net.Conn
	prefix []byte
}

// NewPrefixConn wraps conn so prefix is prepended to the first Write.
func NewPrefixConn(conn net.Conn, prefix []byte) *PrefixConn {
	return &PrefixConn{Conn: conn, prefix: prefix}
}

func (c *PrefixConn) Write(p []byte) (int, error) {
	if c.prefix != nil {
		buf := append(c.prefix, p...)
		c.prefix = nil
		if _, err := c.Conn.Write(buf); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.Conn.Write(p)
}
