package imap

import (
	"context"
	"net"
	"time"

	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/migadu/sora/pkg/metrics"
	serverPkg "github.com/migadu/sora/server"
)

var idlePollInterval = 15 * time.Second

// idleKeepaliveInterval is how often an untagged "* OK Still here" is sent to
// a client sitting in IDLE (Dovecot parity: imap_idle_notify_interval, 2m).
// The write keeps NAT mappings alive and refreshes the SoraConn activity
// clock, so the idle checker (command_timeout) never disconnects a client
// that is legitimately silent in IDLE — RFC 2177 allows up to 29 minutes of
// client silence, and RFC 3501 §5.4 puts the autologout floor at 30 minutes.
var idleKeepaliveInterval = 2 * time.Minute

func (s *IMAPSession) Idle(ctx context.Context, w *imapserver.UpdateWriter, done <-chan struct{}) error {
	s.InfoLog("client entered IDLE mode")

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

	// Keepalive cadence must beat the idle checker: with a command_timeout
	// shorter than the 2m default (tests use seconds), send at half the knob
	// so the activity clock is always refreshed in time.
	keepalive := idleKeepaliveInterval
	if ct := s.server.commandTimeout; ct > 0 && ct/2 < keepalive {
		keepalive = ct / 2
	}

	nextPoll := time.Now().Add(idlePollInterval)
	nextKeepalive := time.Now().Add(keepalive)
	for {
		next := nextPoll
		if nextKeepalive.Before(next) {
			next = nextKeepalive
		}
		if stop, err := s.idleWait(ctx, time.Until(next), done); err != nil || stop {
			return err
		}

		if !time.Now().Before(nextKeepalive) {
			if err := w.WriteOK("Still here"); err != nil {
				return err
			}
			nextKeepalive = time.Now().Add(keepalive)
		}
		if !time.Now().Before(nextPoll) {
			if err := s.Poll(ctx, w, true); err != nil {
				return err
			}
			nextPoll = time.Now().Add(idlePollInterval)
		}
	}
}

func (s *IMAPSession) idleWait(ctx context.Context, d time.Duration, done <-chan struct{}) (stop bool, err error) {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-timer.C:
		return false, nil
	case <-done:
		return true, nil
	case <-ctx.Done():
		// Connection torn down (client disconnect or server shutdown): stop
		// IDLE promptly instead of waiting out the poll interval.
		return true, nil
	}
}
