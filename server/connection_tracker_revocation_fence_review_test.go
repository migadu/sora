package server

import "testing"

func TestRevocationFutureGenerationIsRefused(t *testing.T) {
	for _, state := range []string{"new tracker", "after revocation", "after reset"} {
		t.Run(state, func(t *testing.T) {
			ct := NewConnectionTracker("IMAP", "future-generation", "host", "instance", nil, 0, 0, 0, true)
			t.Cleanup(ct.Stop)
			switch state {
			case "after revocation":
				ct.EndLocalSessions(7)
			case "after reset":
				ct.EndAllLocalSessions()
			}
			future := ct.SessionGeneration() + 1
			if ch := ct.RegisterSessionIfGeneration(42, future); !isClosed(ch) {
				t.Fatal("a generation newer than this tracker registered a session")
			}
			if n := ct.EndLocalSessions(42); n != 0 {
				t.Fatalf("refused registration left %d tracked sessions, want 0", n)
			}
		})
	}
}

func TestRevocationSlotCollisionsStayConservative(t *testing.T) {
	ct := NewConnectionTracker("IMAP", "slot-collision", "host", "instance", nil, 0, 0, 0, true)
	t.Cleanup(ct.Stop)
	const account, alias, laterAlias int64 = 1, 1025, 2049
	generation := ct.SessionGeneration()
	existing := ct.RegisterSessionIfGeneration(account, generation)
	ct.EndLocalSessions(alias)
	if isClosed(existing) {
		t.Fatal("a colliding account closed an already registered session")
	}
	if crossing := ct.RegisterSessionIfGeneration(account, generation); !isClosed(crossing) {
		t.Fatal("a colliding revocation did not conservatively fence the crossing login")
	}
	ct.EndLocalSessions(laterAlias)
	if crossing := ct.RegisterSessionIfGeneration(account, generation); !isClosed(crossing) {
		t.Fatal("a later collision lifted the revocation fence")
	}
	if unrelated := ct.RegisterSessionIfGeneration(2, generation); isClosed(unrelated) {
		t.Fatal("revoking a different slot closed an unrelated login in flight")
	}
	if fresh := ct.RegisterSessionIfGeneration(alias, ct.SessionGeneration()); isClosed(fresh) {
		t.Fatal("a login started after the colliding revocations was refused")
	}
	if n := ct.EndLocalSessions(account); n != 1 || !isClosed(existing) {
		t.Fatalf("own revocation closed %d sessions (closed=%v), want 1 closed session", n, isClosed(existing))
	}
}

func TestRevocationConcurrentRegistrationIsFenced(t *testing.T) {
	for _, action := range []string{"own account", "reset", "other account"} {
		t.Run(action, func(t *testing.T) {
			ct := NewConnectionTracker("IMAP", "concurrent-fence", "host", "instance", nil, 0, 0, 0, true)
			t.Cleanup(ct.Stop)
			for i := 0; i < 32; i++ {
				generation := ct.SessionGeneration()
				start := make(chan struct{})
				registered := make(chan (<-chan struct{}), 1)
				revoked := make(chan struct{})
				go func() {
					<-start
					registered <- ct.RegisterSessionIfGeneration(42, generation)
				}()
				go func() {
					<-start
					switch action {
					case "own account":
						ct.EndLocalSessions(42)
					case "reset":
						ct.EndAllLocalSessions()
					case "other account":
						ct.EndLocalSessions(43)
					}
					close(revoked)
				}()
				close(start)
				ch := <-registered
				<-revoked
				wantClosed := action != "other account"
				if isClosed(ch) != wantClosed {
					t.Fatalf("registration/revocation iteration %d: closed=%v, want %v", i, isClosed(ch), wantClosed)
				}
				ct.UnregisterSession(42, ch)
			}
		})
	}
}
