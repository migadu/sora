package server

import (
	"sync/atomic"
	"testing"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMaintenanceGate_AdmitsAndCounts(t *testing.T) {
	g := NewMaintenanceGate(false)
	var open atomic.Int64
	if !g.Admit(&open, "imap") || !g.Admit(&open, "imap") {
		t.Fatal("a gate that is not refusing refused a session")
	}
	if open.Load() != 2 {
		t.Fatalf("open = %d, want the 2 admitted sessions", open.Load())
	}
}

// A refused session is not counted, and is counted as refused.
func TestMaintenanceGate_RefusesWithoutCounting(t *testing.T) {
	g := NewMaintenanceGate(true)
	var open atomic.Int64
	open.Store(3)
	refused := testutil.ToFloat64(metrics.BackendMaintenanceSessionsRefused.WithLabelValues("pop3"))
	if g.Admit(&open, "pop3") {
		t.Fatal("a refusing gate admitted a session")
	}
	if open.Load() != 3 {
		t.Fatalf("open = %d after a refusal, want it unchanged (3)", open.Load())
	}
	if got := testutil.ToFloat64(metrics.BackendMaintenanceSessionsRefused.WithLabelValues("pop3")); got != refused+1 {
		t.Fatalf("refused sessions metric = %v, want %v", got, refused+1)
	}
}

// Servers built without a gate (tests, nodes that cannot learn their maintenance) admit.
func TestMaintenanceGate_NilAdmits(t *testing.T) {
	var g *MaintenanceGate
	var open atomic.Int64
	if !g.Admit(&open, "lmtp") || open.Load() != 1 {
		t.Fatalf("nil gate: open = %d, want the session admitted and counted", open.Load())
	}
	if g.Refusing() {
		t.Fatal("nil gate reports refusing")
	}
}

func TestMaintenanceGate_SetRefusingReportsAChange(t *testing.T) {
	g := NewMaintenanceGate(false)
	if !g.SetRefusing(true) || g.SetRefusing(true) || !g.Refusing() {
		t.Fatal("want a change only on the first SetRefusing(true), and the gate refusing")
	}
	if !g.SetRefusing(false) || g.Refusing() {
		t.Fatal("want SetRefusing(false) to change it back")
	}
}

// What the node's report relies on: once the gate refuses, a count of zero taken after it
// stays zero. A session counts itself before it looks at the gate, so a reporter that
// refuses and then counts in between the two steps sees it, and it is refused. Looking
// before counting would let it in unseen.
func TestMaintenanceGate_CountsBeforeItLooks(t *testing.T) {
	g := NewMaintenanceGate(false)
	var open atomic.Int64
	reported := int64(-1)
	betweenCountAndLook = func() {
		g.SetRefusing(true)
		reported = open.Load()
	}
	defer func() { betweenCountAndLook = nil }()

	if admitted := g.Admit(&open, "imap"); admitted && reported == 0 {
		t.Fatal("a session got in after a report of refusing with none open")
	}
	if reported != 1 {
		t.Fatalf("the reporter counted %d sessions, want the one being admitted", reported)
	}
}
