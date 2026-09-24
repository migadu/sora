package db

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TestDummyBcryptHash_Valid asserts the dummy hash is a real bcrypt hash at the
// current default cost, and that it tracks BcryptCost changes (it is generated
// lazily so a test package assigning BcryptCost in its own init still gets a
// matching dummy). If it were malformed, CompareHashAndPassword would return
// instantly without doing bcrypt work, silently defeating timing equalization. (M14)
func TestDummyBcryptHash_Valid(t *testing.T) {
	dummy := dummyHashForCurrentCost()
	cost, err := bcrypt.Cost(dummy)
	if err != nil {
		t.Fatalf("dummy hash is not a valid bcrypt hash: %v", err)
	}
	if cost != BcryptCost {
		t.Fatalf("dummy hash cost = %d, want configured BcryptCost %d (timing must match real verifications)", cost, BcryptCost)
	}

	// It must never accidentally match a password.
	if err := bcrypt.CompareHashAndPassword(dummy, []byte("any-password")); err == nil {
		t.Fatal("dummy hash unexpectedly matched a password")
	}

	// The cache must regenerate when the cost changes, so DummyVerifyPassword
	// always burns the same CPU as a real verification at the active cost.
	origCost := BcryptCost
	defer func() {
		BcryptCost = origCost
		dummyHashForCurrentCost() // restore the cached hash for other tests
	}()
	BcryptCost = bcrypt.MinCost
	if cost, err := bcrypt.Cost(dummyHashForCurrentCost()); err != nil || cost != bcrypt.MinCost {
		t.Fatalf("dummy hash did not track cost change: cost=%d err=%v, want %d", cost, err, bcrypt.MinCost)
	}
}

// TestDummyVerifyPassword_Equalizes is the core M14 property: the dummy compare on the
// "account not found" path must cost roughly the same as verifying a real account's
// bcrypt hash, so response time can't be used to enumerate accounts. We compare it
// against a genuine bcrypt verification at the same default cost and require the two
// durations to land in the same ballpark.
func TestDummyVerifyPassword_Equalizes(t *testing.T) {
	// Cost 10 keeps each verify in the tens of milliseconds: long enough that scheduler
	// noise is small next to it, and not MinCost, which the integration build sets
	// globally and where one verify is under a millisecond.
	pinBcryptCost(t, 10)

	realHash, err := bcrypt.GenerateFromPassword([]byte("the-real-password"), BcryptCost)
	if err != nil {
		t.Fatalf("failed to generate real hash: %v", err)
	}

	// Warm up so neither side pays a one-time cost (including the lazy dummy hash).
	_ = bcrypt.CompareHashAndPassword(realHash, []byte("wrong"))
	DummyVerifyPassword("wrong")

	// Interleave the two sides and keep each one's fastest run, so both are exposed to
	// the same conditions and load (which only ever adds time) is filtered out as far
	// as a wall clock allows. On an oversubscribed machine a whole run can still be
	// time-sliced, so a divergent round is retried: a real regression (a no-op dummy,
	// or a dummy at the wrong cost) diverges in every round, while noise does not.
	const rounds, reps = 5, 5
	var realDur, dummyDur time.Duration
	var ratio float64
	for round := 0; round < rounds; round++ {
		realDur, dummyDur = time.Duration(1<<62), time.Duration(1<<62)
		for i := 0; i < reps; i++ {
			start := time.Now()
			_ = bcrypt.CompareHashAndPassword(realHash, []byte("wrong-password"))
			realDur = min(realDur, time.Since(start))

			start = time.Now()
			DummyVerifyPassword("wrong-password")
			dummyDur = min(dummyDur, time.Since(start))
		}

		// The dummy path must do genuine bcrypt work, not a no-op (a string compare is
		// sub-µs). Load can only make it slower, so this needs no retry.
		if dummyDur < time.Millisecond {
			t.Fatalf("DummyVerifyPassword too fast (%v); it is not doing real bcrypt work", dummyDur)
		}

		// Same cost ⇒ same order of magnitude.
		ratio = float64(dummyDur) / float64(realDur)
		if ratio >= 0.5 && ratio <= 2.0 {
			return
		}
		t.Logf("round %d: dummy=%v real=%v ratio=%.2f, retrying", round+1, dummyDur, realDur, ratio)
	}
	t.Fatalf("dummy vs real verification timing diverges in all %d rounds: dummy=%v real=%v ratio=%.2f (want 0.5–2.0)", rounds, dummyDur, realDur, ratio)
}
