package server

import (
	"crypto/tls"
	"errors"
	"net"

	"github.com/migadu/sora/logger"
)

// ProxyProtocolListener reads the PROXY protocol header during Accept, so the
// header is consumed from the raw TCP stream before any TLS wrapper is
// layered on top.
//
// COMPOSITION RULE (see docs/proxy-protocol-tls-composition.md): the PROXY
// header travels in plaintext AHEAD of the TLS ClientHello, so this listener
// must sit BETWEEN the TCP listener and the TLS layer:
//
//	tcpListener → ProxyProtocolListener → SoraTLSListener / tls.NewListener
//
// The TLS handshake then reads THROUGH the ProxyProtocolConn returned here,
// consuming any ClientHello bytes the header parser's bufio buffered
// alongside the header (the kernel frequently delivers header+ClientHello as
// one segment). Wrapping in the other order makes the handshake either read
// the raw socket and miss those buffered bytes, or — with an eager TLS
// listener — handshake against the plaintext "PROXY ..." line itself.
type ProxyProtocolListener struct {
	net.Listener
	reader   *ProxyProtocolReader
	protocol string // protocol label for log lines, e.g. "POP3", "IMAP-PROXY"
}

// NewProxyProtocolListener wraps l so Accept consumes the PROXY header from
// the raw stream. protocol is used only for log lines.
func NewProxyProtocolListener(l net.Listener, reader *ProxyProtocolReader, protocol string) *ProxyProtocolListener {
	return &ProxyProtocolListener{
		Listener: l,
		reader:   reader,
		protocol: protocol,
	}
}

// WrapProxyProtocol composes the PROXY listener into a listener chain,
// returning l unchanged when PROXY support is disabled (reader == nil).
// Call this on the TCP listener BEFORE wrapping the TLS layer.
func WrapProxyProtocol(l net.Listener, reader *ProxyProtocolReader, protocol string) net.Listener {
	if reader == nil {
		return l
	}
	return NewProxyProtocolListener(l, reader, protocol)
}

// Accept returns the next connection with its PROXY header consumed, wrapped
// in a *ProxyProtocolConn carrying the parsed info. Connections with a
// malformed or missing-but-required header are rejected here (closed, loop
// continues) so callers never see per-connection PROXY errors.
func (l *ProxyProtocolListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		proxyInfo, wrappedConn, err := l.reader.ReadProxyHeader(conn)
		if err == nil {
			return &ProxyProtocolConn{
				Conn:      wrappedConn,
				proxyInfo: proxyInfo,
			}, nil
		}

		// Optional mode: no header present is not an error; hand back the
		// (possibly buffered) connection as a direct client.
		if l.reader.IsOptionalMode() && errors.Is(err, ErrNoProxyHeader) {
			logger.Debug("PROXY protocol: no header - treating as direct", "protocol", l.protocol, "remote", GetAddrString(conn.RemoteAddr()))
			return wrappedConn, nil
		}

		// Malformed header, or required mode without a header: reject and
		// keep accepting.
		conn.Close()
		logger.Debug("PROXY protocol: rejecting connection", "protocol", l.protocol, "remote", GetAddrString(conn.RemoteAddr()), "error", err)
		continue
	}
}

// ProxyProtocolConn wraps a connection whose PROXY header has been consumed,
// carrying the parsed client identity. It sits directly above the TCP socket
// (below any TLS layer), so reads through it serve the header parser's
// buffered bytes first.
type ProxyProtocolConn struct {
	net.Conn
	proxyInfo *ProxyProtocolInfo
}

// GetProxyInfo returns the parsed PROXY protocol information.
func (c *ProxyProtocolConn) GetProxyInfo() *ProxyProtocolInfo {
	return c.proxyInfo
}

// Unwrap returns the underlying connection for wrapper-chain walks.
func (c *ProxyProtocolConn) Unwrap() net.Conn {
	return c.Conn
}

// GetProxyProtocolInfo walks conn's wrapper chain and returns the PROXY
// protocol info, or nil when the connection has none. It traverses Unwrap()
// wrappers and *tls.Conn (via NetConn(), which never triggers a handshake),
// and accepts any layer exposing GetProxyInfo() — e.g. ProxyProtocolConn or a
// limiter conn caching the info.
//
// ORDERING: on deferred-handshake chains (SoraTLSConn) call this BEFORE the
// TLS handshake where possible — PerformHandshake swaps the SoraConn's
// underlying conn to the *tls.Conn. The walk still gets through afterwards
// (tls.Conn → NetConn → bufferedConn.Unwrap → ProxyProtocolConn), but
// anything gating on the real client IP (limiters, master-SASL nets) must
// have run pre-handshake anyway.
func GetProxyProtocolInfo(conn net.Conn) *ProxyProtocolInfo {
	for conn != nil {
		if pc, ok := conn.(interface{ GetProxyInfo() *ProxyProtocolInfo }); ok {
			if info := pc.GetProxyInfo(); info != nil {
				return info
			}
		}
		switch c := conn.(type) {
		case *tls.Conn:
			conn = c.NetConn()
		case interface{ Unwrap() net.Conn }:
			conn = c.Unwrap()
		default:
			return nil
		}
	}
	return nil
}
