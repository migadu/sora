package server

import (
	"sync/atomic"

	"github.com/migadu/sora/pkg/metrics"
)

// MaintenanceGate is how a backend in maintenance refuses new sessions itself: the
// sessions it must let finish before it stops (IMAP and POP3 logins, LMTP transactions,
// Admin API deliveries), however they reach it. The proxies stop routing to it, but
// something that bypasses them (direct ingress, a proxy on an older build) would otherwise
// still start one, and `sora-admin backends ... --wait` could call the node safe to stop
// just as it did.
//
// The node's sessions reporter sets it before it counts the open sessions, and every
// session counts itself before it looks at it (Admit). A report of refusing and none open
// therefore holds after the report too: a session that got in was counted first, so the
// count includes it, or it looked after refusing began and was refused.
//
// A nil gate admits everything: servers built without one (tests, a node with no sessions
// report) never refuse.
type MaintenanceGate struct {
	refusing atomic.Bool
}

// NewMaintenanceGate returns a gate, refusing new sessions or not.
func NewMaintenanceGate(refusing bool) *MaintenanceGate {
	g := &MaintenanceGate{}
	g.refusing.Store(refusing)
	return g
}

// Admit counts a session that is about to begin in open, and reports whether it may. A
// session it refuses is not counted (and is counted under protocol in
// sora_backend_maintenance_sessions_refused_total); the caller answers with a temporary
// failure. The order (count, then look) is what the node's report relies on.
func (g *MaintenanceGate) Admit(open *atomic.Int64, protocol string) bool {
	open.Add(1)
	if betweenCountAndLook != nil {
		betweenCountAndLook()
	}
	if g.Refusing() {
		open.Add(-1)
		metrics.BackendMaintenanceSessionsRefused.WithLabelValues(protocol).Inc()
		return false
	}
	return true
}

// betweenCountAndLook, set only by tests, runs between Admit's two steps: where a reporter
// that refuses and counts would have to fall for a session to slip past it.
var betweenCountAndLook func()

// Refusing reports whether new sessions are refused.
func (g *MaintenanceGate) Refusing() bool {
	return g != nil && g.refusing.Load()
}

// SetRefusing makes the gate refuse new sessions, or admit them again, and reports
// whether that changed anything.
func (g *MaintenanceGate) SetRefusing(refusing bool) bool {
	return g.refusing.Swap(refusing) != refusing
}
