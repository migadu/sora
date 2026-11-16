package server

import "testing"

func TestRevocationFencesSessionRegisteredAfterRemoval(t *testing.T) {
	ct := NewConnectionTracker("IMAP", "revocation-generation", "host", "instance", nil, 0, 0, 0, true)
	t.Cleanup(ct.Stop)
	started, register := make(chan struct{}), make(chan struct{})
	done := make(chan (<-chan struct{}), 1)
	go func() {
		generation := ct.SessionGeneration() // authentication starts
		close(started)
		<-register // its credential read/verification completes after revocation
		done <- ct.RegisterSessionIfGeneration(42, generation)
	}()
	<-started
	ct.EndLocalSessions(42) // no session registered yet, but the removal must fence it
	close(register)
	late := <-done
	select {
	case <-late:
	default:
		t.Fatal("late authenticated session missed removal")
	}
	fresh := ct.RegisterSessionIfGeneration(7, ct.SessionGeneration())
	select {
	case <-fresh:
		t.Fatal("fresh generation was refused")
	default:
	}
	if n := ct.EndAllLocalSessions(); n != 1 {
		t.Fatalf("reset closed %d sessions, want1", n)
	}
	select {
	case <-fresh:
	default:
		t.Fatal("reset left a local session open")
	}
	var disabled *ConnectionTracker
	select {
	case <-disabled.RegisterSessionIfGeneration(1, 0):
		t.Fatal("nil tracker changed legacy behavior")
	default:
	}
}
