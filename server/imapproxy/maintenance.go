package imapproxy

import (
	"io"
	"net"
	"time"

	"github.com/migadu/sora/server/proxy"
)

// maintenanceCloseGrace bounds how long a session closed for backend maintenance may take
// to end. It normally ends sooner, as soon as the backend has answered the commands it
// already had and closed. A variable so tests can shorten it.
var maintenanceCloseGrace = 30 * time.Second

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
//     session ends with it (the copy closes the client), or after maintenanceCloseGrace.
//
// A session that is already closing is left alone, so it is never closed (or sent a BYE)
// twice.
func (s *Session) closeForMaintenance() {
	s.mu.Lock()
	if s.gracefulShutdown {
		s.mu.Unlock()
		return
	}
	// The copy goroutine must not close clientConn before the BYE is written; once the
	// backend has closed, it does (closingForMaintenance).
	s.gracefulShutdown = true
	s.closingForMaintenance = true
	backendConn := s.backendConn
	s.mu.Unlock()
	s.InfoLog("closing session: backend in maintenance", "backend", s.serverAddrLocked())

	if closeWriter, ok := backendConn.(interface{ CloseWrite() error }); ok {
		if err := closeWriter.CloseWrite(); err != nil {
			s.DebugLog("Failed to half-close backend connection", "error", err)
		}
	}
	// Not inline: sendBye waits for a write the copy has under way, and the drain must not.
	go s.sendBye(byeMaintenance)
	time.AfterFunc(maintenanceCloseGrace, func() {
		s.mu.Lock()
		clientConn, backendConn := s.clientConn, s.backendConn
		s.mu.Unlock()
		if backendConn != nil {
			backendConn.Close()
		}
		if clientConn != nil {
			clientConn.Close()
		}
	})
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
