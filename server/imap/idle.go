package imap

import (
	"net"
	"time"

	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/pkg/metrics"
	serverPkg "github.com/migadu/sora/server"
)

var idlePollInterval = 15 * time.Second

func (s *IMAPSession) Idle(w *imapserver.UpdateWriter, done <-chan struct{}) error {
	s.Log("client entered IDLE mode")

	metrics.IMAPIdleConnections.Inc()
	defer metrics.IMAPIdleConnections.Dec()

	// Suspend throughput checking when entering IDLE
	// IDLE is expected to have minimal traffic (just periodic "still here" responses)
	// and legitimate clients may stay idle for 29 minutes waiting for new mail.
	// The slowloris protection would incorrectly flag these as attacks.
	if netConn := s.conn.NetConn(); netConn != nil {
		// Try direct cast first
		if tc, ok := netConn.(*serverPkg.SoraConn); ok {
			tc.SuspendThroughputChecking()
			defer tc.ResumeThroughputChecking()
		} else {
			// Try to unwrap if it's wrapped
			type unwrapper interface {
				Unwrap() net.Conn
			}
			if uw, ok := netConn.(unwrapper); ok {
				if tc, ok := uw.Unwrap().(*serverPkg.SoraConn); ok {
					tc.SuspendThroughputChecking()
					defer tc.ResumeThroughputChecking()
				}
			}
		}
	}

	for {
		if stop, err := s.idleLoop(w, done); err != nil {
			return err
		} else if stop {
			return nil
		}
	}
}

func (s *IMAPSession) idleLoop(w *imapserver.UpdateWriter, done <-chan struct{}) (stop bool, err error) {
	timer := time.NewTimer(idlePollInterval)
	defer timer.Stop()

	select {
	case <-timer.C:
		return false, s.Poll(w, true)
	case <-done:
		return true, nil
	}
}
