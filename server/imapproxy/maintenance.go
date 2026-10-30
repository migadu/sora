package imapproxy

import (
	"fmt"
	"time"

	"github.com/migadu/sora/server/proxy"
)

// maintenanceByeDelay is how long a session closed for backend maintenance stays open
// after its BYE, so the client reads it before the connection goes (as on shutdown).
const maintenanceByeDelay = time.Second

// MaintenanceTargets lists the active sessions with the backend each is connected to,
// for the drain that closes sessions on backends in maintenance (proxy.StartSessionDrainer).
// IMAP is the protocol that needs it: a session can stay for hours (IDLE) and keep
// APPENDing, which would keep adding uploads to a node that is meant to be emptying.
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
		if session.backendConn != nil {
			backend = session.serverAddr
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
// connections close — sendGracefulShutdownBye's sequence, for one session. Safe to call on
// a session that is already closing.
func (s *Session) closeForMaintenance() {
	s.mu.Lock()
	// The copy goroutine must not close clientConn before the BYE is written.
	s.gracefulShutdown = true
	if s.clientConn != nil {
		// Bounded: a client that stopped reading must not hold the drain (or this
		// session's mutex). The session is closing anyway, so the deadline costs nothing.
		_ = s.clientConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = fmt.Fprint(s.clientConn, "* BYE [UNAVAILABLE] Server in maintenance, please reconnect\r\n")
	}
	s.mu.Unlock()
	s.InfoLog("closing session: backend in maintenance", "backend", s.serverAddrLocked())

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
