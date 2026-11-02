package imapproxy

import (
	"io"
	"net"
	"time"

	"github.com/migadu/sora/server/proxy"
)

// maintenanceByeDelay is how long a session closed for backend maintenance stays open
// after its BYE, so the client reads it before the connection goes (as on shutdown).
const maintenanceByeDelay = time.Second

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
		if session.backendConn != nil && !session.gracefulShutdown { // not already closing
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

// closeForMaintenance ends a session whose backend went into maintenance: BYE
// [UNAVAILABLE] so the client reconnects at once (and is routed elsewhere), then both
// connections close — sendGracefulShutdownBye's sequence, for one session. A session that
// is already closing is left alone, so it is never closed (or sent a BYE) twice.
func (s *Session) closeForMaintenance() {
	s.mu.Lock()
	if s.gracefulShutdown {
		s.mu.Unlock()
		return
	}
	// The copy goroutine must not close clientConn before the BYE is written.
	s.gracefulShutdown = true
	s.mu.Unlock()
	s.InfoLog("closing session: backend in maintenance", "backend", s.serverAddrLocked())

	// Not inline: sendBye waits for a write the copy has under way, and the drain must not.
	go s.sendBye(byeMaintenance)
	time.AfterFunc(maintenanceByeDelay, func() {
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
// writes it there). After the BYE nothing from the backend is forwarded. If the response
// does not end before the session closes, no BYE is written at all: the client, cut off
// inside a response, discards it, where a BYE could have been read as part of it.
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
// response under way, then the BYE, and drops the rest; after a BYE it drops everything.
// Dropped bytes count as written: the session is closing.
func (s *Session) forwardToClient(dst net.Conn, p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.byeSent {
		return len(p), nil
	}
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
	_, err := io.WriteString(dst, s.byePending)
	s.byePending, s.byeSent = "", true
	return len(p), err
}
