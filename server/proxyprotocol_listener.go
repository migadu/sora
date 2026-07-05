package server

import (
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"github.com/migadu/sora/logger"
)

// maxConcurrentHeaderReads bounds the number of connections that may be
// parsing their PROXY header simultaneously (per listener). Each pending
// parse holds one goroutine and one FD for at most the header timeout, so
// this cap only becomes backpressure (accept pauses) under a flood of
// header-less connections; a healthy proxy fleet delivers headers in
// microseconds and never approaches it.
const maxConcurrentHeaderReads = 1024

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
//
// CONCURRENCY: header reads run in a per-connection goroutine, NOT in the
// accept path. A peer that connects and never sends its header stalls only
// its own connection (closed after the header timeout) — it cannot
// head-of-line block other clients behind a serial Accept. This matters in
// production: with a required-mode 5s header timeout, a single misconfigured
// peer (a proxy without remote_use_proxy_protocol, a TCP health probe)
// dribbling connections would otherwise starve the whole listener and
// manifest as backend-greeting timeouts fleet-wide.
type ProxyProtocolListener struct {
	net.Listener
	reader   *ProxyProtocolReader
	protocol string // protocol label for log lines, e.g. "POP3", "IMAP-PROXY"

	// clientAddrOverride makes delivered conns report the PROXY-forwarded
	// client address from RemoteAddr() — net/http stacks only (see
	// WrapProxyProtocolHTTP).
	clientAddrOverride bool

	ready chan net.Conn // header-parsed conns handed to Accept
	errCh chan error    // accept errors relayed to Accept (transient and fatal)

	closeOnce sync.Once
	closed    chan struct{} // closed by Close (or a fatal pump error); releases pump, parsers, Accept

	// finalErr is the fatal accept error, recorded before closed is closed so
	// repeated Accept calls after shutdown keep returning it (callers that
	// treat accept errors as transient re-call Accept and must not block).
	finalErrMu sync.Mutex
	finalErr   error

	sem chan struct{} // caps concurrent header parses
}

// NewProxyProtocolListener wraps l so Accept returns connections with their
// PROXY header already consumed. protocol is used only for log lines.
func NewProxyProtocolListener(l net.Listener, reader *ProxyProtocolReader, protocol string) *ProxyProtocolListener {
	pl := &ProxyProtocolListener{
		Listener: l,
		reader:   reader,
		protocol: protocol,
		ready:    make(chan net.Conn),
		errCh:    make(chan error),
		closed:   make(chan struct{}),
		sem:      make(chan struct{}, maxConcurrentHeaderReads),
	}
	go pl.acceptPump()
	return pl
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

// WrapProxyProtocolHTTP is the net/http variant of WrapProxyProtocol:
// delivered connections additionally override RemoteAddr() with the
// PROXY-forwarded client address. net/http derives r.RemoteAddr from
// conn.RemoteAddr() and offers no other channel for the real client IP, so
// HTTP middleware (allowed_hosts, rate limiting, logging) needs the override.
//
// Socket-protocol servers must NOT use this variant: their limiters and
// master-SASL network gates deliberately anchor on the raw socket peer and
// take the client IP from the PROXY info separately.
func WrapProxyProtocolHTTP(l net.Listener, reader *ProxyProtocolReader, protocol string) net.Listener {
	if reader == nil {
		return l
	}
	pl := NewProxyProtocolListener(l, reader, protocol)
	pl.clientAddrOverride = true
	return pl
}

// acceptPump owns the underlying Accept loop: it accepts raw connections and
// hands each to its own parser goroutine, so the pump returns to Accept
// immediately. Underlying accept errors are relayed to Accept callers;
// transient ones (e.g. EMFILE) do not stop the pump, a closed listener does.
func (l *ProxyProtocolListener) acceptPump() {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				// Fatal: record it and release everyone. Repeated Accept
				// calls keep returning this error via the closed branch.
				l.finalErrMu.Lock()
				l.finalErr = err
				l.finalErrMu.Unlock()
				l.closeOnce.Do(func() {
					close(l.closed)
					l.Listener.Close()
				})
				return
			}
			// Transient (e.g. EMFILE): relay to one Accept caller, keep
			// pumping — matching the serial listener, which returned the
			// error and accepted again on the caller's next Accept call.
			select {
			case l.errCh <- err:
			case <-l.closed:
				return
			}
			continue
		}

		// Backpressure: at the cap, wait for a parser slot instead of
		// spawning unboundedly. Close() unblocks this wait.
		select {
		case l.sem <- struct{}{}:
		case <-l.closed:
			conn.Close()
			return
		}
		go l.parseHeader(conn)
	}
}

// parseHeader consumes one connection's PROXY header (bounded by the reader's
// own timeout) and delivers the wrapped conn to Accept. Failed connections
// are closed here; Accept callers never see per-connection PROXY errors.
func (l *ProxyProtocolListener) parseHeader(conn net.Conn) {
	defer func() { <-l.sem }()

	proxyInfo, wrappedConn, err := l.reader.ReadProxyHeader(conn)

	var out net.Conn
	switch {
	case err == nil:
		pc := &ProxyProtocolConn{
			Conn:      wrappedConn,
			proxyInfo: proxyInfo,
		}
		if l.clientAddrOverride && proxyInfo != nil && proxyInfo.SrcIP != "" {
			out = &proxyClientAddrConn{ProxyProtocolConn: pc}
		} else {
			out = pc
		}
	case l.reader.IsOptionalMode() && errors.Is(err, ErrNoProxyHeader):
		// Optional mode: no header present is not an error; hand back the
		// (possibly buffered) connection as a direct client.
		logger.Debug("PROXY protocol: no header - treating as direct", "protocol", l.protocol, "remote", GetAddrString(conn.RemoteAddr()))
		out = wrappedConn
	case errors.Is(err, ErrUntrustedProxySource):
		// Untrusted peers are expected background noise (scanners, direct
		// clients hitting a proxied port); keep them quiet.
		conn.Close()
		logger.Debug("PROXY protocol: rejecting connection", "protocol", l.protocol, "remote", GetAddrString(conn.RemoteAddr()), "error", err)
		return
	default:
		// A TRUSTED peer that failed to deliver a header (timeout, malformed)
		// is a fleet misconfiguration signal — e.g. a proxy dialing without
		// remote_use_proxy_protocol against a required-mode listener. Loud on
		// purpose: this failure mode is otherwise only visible as mysterious
		// client-side timeouts.
		conn.Close()
		logger.Warn("PROXY protocol: rejecting connection from TRUSTED peer (missing/invalid header - check the peer's remote_use_proxy_protocol / health-probe config)",
			"protocol", l.protocol, "remote", GetAddrString(conn.RemoteAddr()), "error", err)
		return
	}

	select {
	case l.ready <- out:
	case <-l.closed:
		out.Close()
	}
}

// Accept returns the next connection whose PROXY header has been consumed,
// wrapped in a *ProxyProtocolConn carrying the parsed info (or the bare conn
// in optional mode with no header). Connections may be returned in a
// different order than they arrived: header parsing is concurrent.
func (l *ProxyProtocolListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.ready:
		return conn, nil
	case err := <-l.errCh:
		return nil, err
	case <-l.closed:
		l.finalErrMu.Lock()
		err := l.finalErr
		l.finalErrMu.Unlock()
		if err == nil {
			err = net.ErrClosed
		}
		return nil, err
	}
}

// Close stops the listener: it releases the pump, any in-flight parser
// deliveries, and blocked Accept callers, then closes the underlying
// listener. Idempotent.
func (l *ProxyProtocolListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		close(l.closed)
		err = l.Listener.Close()
	})
	return err
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

// proxyClientAddrConn is a ProxyProtocolConn whose RemoteAddr() reports the
// PROXY-forwarded client address instead of the socket peer. Used only by
// WrapProxyProtocolHTTP: net/http derives r.RemoteAddr from conn.RemoteAddr()
// and has no other channel for the real client IP. Socket-protocol servers
// must never see this type — their limiters and master-SASL gates anchor on
// the raw peer.
type proxyClientAddrConn struct {
	*ProxyProtocolConn
}

func (c *proxyClientAddrConn) RemoteAddr() net.Addr {
	info := c.GetProxyInfo()
	if ip := net.ParseIP(info.SrcIP); ip != nil {
		return &net.TCPAddr{IP: ip, Port: info.SrcPort}
	}
	return c.ProxyProtocolConn.RemoteAddr()
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
