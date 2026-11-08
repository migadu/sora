package imapproxy

import (
	"crypto/tls"
	"io"
	"net"
	"time"

	"github.com/migadu/sora/server/proxy"
)

// maintenanceCloseGrace bounds how long a session closed for backend maintenance may take
// to end. It normally ends sooner, as soon as the backend has answered the commands it
// already had and closed. A variable so tests can shorten it.
var maintenanceCloseGrace = 30 * time.Second

// maintenanceLinger bounds how long a session closed for maintenance goes on reading the
// client's input once the backend has closed, for the client to close its end first. A
// variable so tests can shorten it.
var maintenanceLinger = 2 * time.Second

// byeMaintenance is the BYE of a session closed for backend maintenance.
const byeMaintenance = "* BYE [UNAVAILABLE] Server in maintenance, please reconnect\r\n"

// MaintenanceTargets lists the active sessions with the backend each is connected to,
// for the drain that closes sessions on backends in maintenance (proxy.StartSessionDrainer).
// IMAP is the protocol that needs it: a session can stay for hours (IDLE) and keep
// APPENDing, which would keep adding uploads to a node that is meant to be emptying.
//
// The backend is the address the connection is actually connected to, not the name it
// was routed by, so a session is found whatever name led it to a backend in maintenance.
func (s *Server) MaintenanceTargets() []proxy.DrainTarget {
	s.activeSessionsMu.RLock()
	sessions := make([]*Session, 0, len(s.activeSessions))
	for session := range s.activeSessions {
		sessions = append(sessions, session)
	}
	s.activeSessionsMu.RUnlock()

	targets := make([]proxy.DrainTarget, 0, len(sessions))
	for _, session := range sessions {
		session.mu.Lock()
		backend := ""
		// Proxying (past its login reply, which a BYE must not overtake) and not already closing.
		if session.proxying && session.backendConn != nil && !session.gracefulShutdown {
			backend = session.serverAddr
			if remote := session.backendConn.RemoteAddr(); remote != nil {
				backend = remote.String()
			}
		}
		session.mu.Unlock()
		if backend != "" {
			targets = append(targets, proxy.DrainTarget{Backend: backend, Close: session.closeForMaintenance})
		}
	}
	return targets
}

// closeForMaintenance ends a session whose backend went into maintenance, so the client
// reconnects (and is routed elsewhere) without losing the outcome of anything it sent:
//
//   - the backend's write side is shut, so no command the client sends from now on reaches
//     it, while the commands it already has run to completion;
//   - BYE [UNAVAILABLE] goes to the client between two responses (sendBye), and the
//     backend's replies keep flowing after it: a client that saw no tagged OK for an APPEND
//     it sent would send it again after reconnecting, and the mail would be there twice;
//   - the backend, at the end of its input, answers what it had and closes, and the
//     session ends with it (endForMaintenance), or after maintenanceCloseGrace.
//
// A session that is already closing is left alone, so it is never closed (or sent a BYE)
// twice.
func (s *Session) closeForMaintenance() {
	s.mu.Lock()
	if s.gracefulShutdown {
		s.mu.Unlock()
		return
	}
	// The copies no longer close clientConn (gracefulShutdown): the session ends with
	// endForMaintenance once the backend has closed (closingForMaintenance).
	s.gracefulShutdown = true
	s.closingForMaintenance = true
	backendConn := s.backendConn
	clientConn := s.clientConn
	s.mu.Unlock()
	s.InfoLog("closing session: backend in maintenance", "backend", s.serverAddrLocked())

	// Arm the bound before any network operation. TLS CloseWrite sends an alert
	// and can wait for a stalled peer or for an existing Write's TLS mutex. The
	// drain's pacing loop must not wait for any one session to finish that work.
	time.AfterFunc(maintenanceCloseGrace, func() {
		closeMaintenanceTransport(clientConn)
		closeMaintenanceTransport(backendConn)
	})
	go func() {
		if closeWriter, ok := backendConn.(interface{ CloseWrite() error }); ok {
			if err := closeWriter.CloseWrite(); err != nil {
				s.DebugLog("Failed to half-close backend connection", "error", err)
			}
		}
		// The BYE follows the half-close, so commands sent after it cannot reach
		// the backend. Already accepted commands still get their responses.
		s.sendBye(byeMaintenance)
	}()
}

// closeMaintenanceTransport forces the socket closed at the end of the grace
// period, then lets outer wrappers release their bookkeeping. tls.Conn.Close
// alone can wait for the very close_notify write this deadline must interrupt.
func closeMaintenanceTransport(conn net.Conn) {
	if conn == nil {
		return
	}
	transport := conn
	unwrapped := false
	for {
		switch c := transport.(type) {
		case *tls.Conn:
			transport = c.NetConn()
		case interface{ Unwrap() net.Conn }:
			transport = c.Unwrap()
		default:
			_ = transport.Close()
			if unwrapped {
				_ = conn.Close()
			}
			return
		}
		unwrapped = true
	}
}

// endForMaintenance ends a session closed for maintenance, once its backend has closed.
// The BYE goes out first if it has not yet: the backend can close before sendBye ran.
// The client then has maintenanceLinger to close its end, and what it sends meanwhile is
// read and dropped (drainClientInput), so that the proxy does not close the connection
// with input unread: that close is a reset, and a reset can discard what the client has
// not read yet, such as the tagged OK of an APPEND it would then send again.
func (s *Session) endForMaintenance() {
	s.sendBye(byeMaintenance)
	s.mu.Lock()
	conn := s.clientConn
	s.mu.Unlock()
	if conn != nil {
		_ = conn.SetReadDeadline(time.Now().Add(maintenanceLinger))
	}
}

// drainClientInput reads and drops what the client sends once its session is closed for
// maintenance and its commands no longer reach the backend, until the client closes its
// end or endForMaintenance's deadline passes.
func (s *Session) drainClientInput() {
	_, _ = io.Copy(io.Discard, s.clientConn)
}

// isClosingForMaintenance reports whether closeForMaintenance has run.
func (s *Session) isClosingForMaintenance() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closingForMaintenance
}

// serverAddrLocked reads the session's backend address under its mutex, for callers on a
// goroutine other than the session's.
func (s *Session) serverAddrLocked() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serverAddr
}

// sendBye has bye written to the client between two responses: at once if the backend's
// stream stands between responses, else as soon as the response under way ends (the copy
// writes it there). Responses after it are still forwarded, as tagged replies follow the
// BYE of a LOGOUT. If the response under way does not end before the session closes, no BYE
// is written at all: the client, cut off inside a response, discards it, where a BYE could
// have been read as part of it.
func (s *Session) sendBye(bye string) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.byeSent || s.byePending != "" {
		return
	}
	if !s.resp.atBoundary() {
		s.byePending = bye
		return
	}
	s.mu.Lock()
	conn := s.clientConn
	s.mu.Unlock()
	if conn == nil {
		return
	}
	// Bounded: a client that stopped reading must not hold this goroutine. The session
	// is closing anyway, so the deadline costs nothing.
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(conn, bye)
	s.byeSent = true
}

// forwardToClient writes a chunk of the backend's response stream to the client, keeping
// track of where the stream stands. With a BYE pending it writes up to the end of the
// response under way, then the BYE, then the rest.
func (s *Session) forwardToClient(dst net.Conn, p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.byePending == "" {
		s.resp.consume(p, false)
		return dst.Write(p)
	}
	n := s.resp.consume(p, true)
	if !s.resp.atBoundary() {
		return dst.Write(p)
	}
	if nw, err := dst.Write(p[:n]); err != nil {
		return nw, err
	}
	if _, err := io.WriteString(dst, s.byePending); err != nil {
		return n, err
	}
	s.byePending, s.byeSent = "", true
	s.resp.consume(p[n:], false)
	nw, err := dst.Write(p[n:])
	return n + nw, err
}
