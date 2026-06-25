package db

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// TestDummyBcryptHash_Valid asserts the package-level dummy hash is a real bcrypt hash at
// the current default cost. If it were malformed, CompareHashAndPassword would return
// instantly without doing bcrypt work, silently defeating timing equalization. (M14)
func TestDummyBcryptHash_Valid(t *testing.T) {
	cost, err := bcrypt.Cost(dummyBcryptHash)
	if err != nil {
		t.Fatalf("dummyBcryptHash is not a valid bcrypt hash: %v", err)
	}
	if cost != BcryptCost {
		t.Fatalf("dummyBcryptHash cost = %d, want configured BcryptCost %d (timing must match real verifications)", cost, BcryptCost)
	}

	// It must never accidentally match a password.
	if err := bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte("any-password")); err == nil {
		t.Fatal("dummyBcryptHash unexpectedly matched a password")
	}
}

// TestDummyVerifyPassword_Equalizes is the core M14 property: the dummy compare on the
// "account not found" path must cost roughly the same as verifying a real account's
// bcrypt hash, so response time can't be used to enumerate accounts. We compare it
// against a genuine bcrypt verification at the same default cost and require the two
// durations to land in the same ballpark.
func TestDummyVerifyPassword_Equalizes(t *testing.T) {
	realHash, err := bcrypt.GenerateFromPassword([]byte("the-real-password"), BcryptCost)
	if err != nil {
		t.Fatalf("failed to generate real hash: %v", err)
	}

	// Warm up so neither side pays a one-time cost in the measured run.
	_ = bcrypt.CompareHashAndPassword(realHash, []byte("wrong"))
	DummyVerifyPassword("wrong")

	const reps = 5
	timeIt := func(fn func()) time.Duration {
		start := time.Now()
		for i := 0; i < reps; i++ {
			fn()
		}
		return time.Since(start) / reps
	}

	realDur := timeIt(func() { _ = bcrypt.CompareHashAndPassword(realHash, []byte("wrong-password")) })
	dummyDur := timeIt(func() { DummyVerifyPassword("wrong-password") })

	// The dummy path must do genuine bcrypt work, not a no-op (a string compare is sub-µs).
	if dummyDur < time.Millisecond {
		t.Fatalf("DummyVerifyPassword too fast (%v); it is not doing real bcrypt work", dummyDur)
	}

	// Same cost ⇒ same order of magnitude. Allow a wide band to stay non-flaky on shared CI.
	ratio := float64(dummyDur) / float64(realDur)
	if ratio < 0.5 || ratio > 2.0 {
		t.Fatalf("dummy vs real verification timing diverges: dummy=%v real=%v ratio=%.2f (want 0.5–2.0)", dummyDur, realDur, ratio)
	}
}
