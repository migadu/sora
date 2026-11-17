package server

import "testing"

// isClosed reports whether a kick channel has been closed.
func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

// TestRevocationOfOneAccountDoesNotFenceOtherAccountsLogins: ending the sessions of
// some accounts (a kick, a removal, a credential change) must not close a login of
// another account that was in flight at that moment (#1882). The ALPS browser tests
// saw account 1's ManageSieve logins closed right after OK whenever the test deleted
// accounts 2-10.
func TestRevocationOfOneAccountDoesNotFenceOtherAccountsLogins(t *testing.T) {
	ct := NewConnectionTracker("ManageSieve", "fence-per-account", "host", "instance", nil, 0, 0, 0, true)
	t.Cleanup(ct.Stop)

	generation := ct.SessionGeneration() // account 1's authentication starts
	for id := int64(2); id <= 10; id++ {
		ct.EndLocalSessions(id) // the accounts the test deletes
	}
	ct.applyKick(11, "") // and a kick of yet another account
	if late := ct.RegisterSessionIfGeneration(1, generation); isClosed(late) {
		t.Fatal("ending other accounts' sessions closed account 1's login in flight")
	}
}

// TestRevocationStillFencesTheRevokedAccountsLoginInFlight: the guarantee the node-wide
// fence gave must hold per account: a login of the revoked account that captured the
// generation before the revocation is refused, whatever else happened in between.
func TestRevocationStillFencesTheRevokedAccountsLoginInFlight(t *testing.T) {
	ct := NewConnectionTracker("IMAP", "fence-per-account-revoked", "host", "instance", nil, 0, 0, 0, true)
	t.Cleanup(ct.Stop)

	generation := ct.SessionGeneration()
	ct.EndLocalSessions(42)
	for id := int64(100); id < 200; id++ {
		ct.EndLocalSessions(id) // later revocations of other accounts must not unfence 42
	}
	if late := ct.RegisterSessionIfGeneration(42, generation); !isClosed(late) {
		t.Fatal("a login of the removed account in flight across its removal was registered")
	}
	// A kick fences in the same way.
	generation = ct.SessionGeneration()
	ct.applyKick(43, "")
	if late := ct.RegisterSessionIfGeneration(43, generation); !isClosed(late) {
		t.Fatal("a login of the kicked account in flight across its kick was registered")
	}
	// A login that starts after the account's revocation is not fenced by it.
	if fresh := ct.RegisterSessionIfGeneration(42, ct.SessionGeneration()); isClosed(fresh) {
		t.Fatal("a login started after the account's removal was refused")
	}
}

// TestResetStillFencesEveryLoginInFlight: the fail-closed reset after a revocation-history
// gap does not know which accounts changed, so it must fence every login in flight.
func TestResetStillFencesEveryLoginInFlight(t *testing.T) {
	ct := NewConnectionTracker("POP3", "fence-per-account-reset", "host", "instance", nil, 0, 0, 0, true)
	t.Cleanup(ct.Stop)

	generation := ct.SessionGeneration()
	ct.EndAllLocalSessions()
	ct.EndLocalSessions(5) // a later per-account revocation must not lift the reset's fence
	for _, id := range []int64{1, 2, 3, 1 << 40} {
		if late := ct.RegisterSessionIfGeneration(id, generation); !isClosed(late) {
			t.Fatalf("account %d's login in flight across a reset was registered", id)
		}
	}
	if fresh := ct.RegisterSessionIfGeneration(1, ct.SessionGeneration()); isClosed(fresh) {
		t.Fatal("a login started after the reset was refused")
	}
}
