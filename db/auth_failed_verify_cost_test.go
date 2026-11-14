package db

import (
	"errors"
	"testing"
	"time"

	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"golang.org/x/crypto/bcrypt"
)

// TestFailedVerificationCostsWhatAnUnknownAddressCosts: a wrong password for an
// existing account takes as long as a login for an address with no account
// (DummyVerifyPassword, one bcrypt comparison at BcryptCost), whatever the scheme of
// the account's hash and whatever its bcrypt cost up to BcryptCost. Otherwise the
// response time tells which addresses have an account (#847). A hash above
// BcryptCost cannot be checked any faster; the rehash after a successful login
// brings it down to BcryptCost.
func TestFailedVerificationCostsWhatAnUnknownAddressCosts(t *testing.T) {
	// Cost 10, as in TestDummyVerifyPassword_Equalizes: tens of milliseconds per
	// comparison, and not the MinCost the integration build sets globally.
	pinBcryptCost(t, 10)

	ssha512, err := GenerateSSHA512Hash("the-real-password")
	if err != nil {
		t.Fatal(err)
	}
	bcryptAt := func(cost int) string {
		h, err := bcrypt.GenerateFromPassword([]byte("the-real-password"), cost)
		if err != nil {
			t.Fatal(err)
		}
		return string(h)
	}

	cases := []struct {
		name string
		hash string
	}{
		{"SSHA512", ssha512},
		{"SHA512", GenerateSHA512Hash("the-real-password")},
		{"bcrypt at BcryptCost", bcryptAt(BcryptCost)},
		{"bcrypt one below BcryptCost", bcryptAt(BcryptCost - 1)},
		{"BLF-CRYPT three below BcryptCost", blfCryptPrefix + bcryptAt(BcryptCost-3)},
	}

	DummyVerifyPassword("warm-up")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Warm-up, which also checks that the password is refused, and refused as
			// one verification: the work spent on it is not a dummy verification
			// (testutils.PasswordVerifications counts one per failed login).
			dummies := testutil.ToFloat64(metrics.PasswordDummyVerifications)
			if err := VerifyPassword(tc.hash, "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("VerifyPassword with a wrong password: %v, want ErrInvalidCredentials", err)
			}
			if got := testutil.ToFloat64(metrics.PasswordDummyVerifications) - dummies; got != 0 {
				t.Fatalf("a failed VerifyPassword counted %v dummy verifications, want 0", got)
			}

			// Interleave the two sides and keep each one's fastest run, retrying a
			// divergent round, as TestDummyVerifyPassword_Equalizes does. The bounds are
			// tighter than its 0.5-2.0: a bcrypt hash one cost below BcryptCost takes
			// half as long, and one comparison at BcryptCost on top of it 1.5 times.
			const rounds, reps = 5, 5
			var verifyDur, dummyDur time.Duration
			var ratio float64
			for round := 0; round < rounds; round++ {
				verifyDur, dummyDur = time.Duration(1<<62), time.Duration(1<<62)
				for i := 0; i < reps; i++ {
					start := time.Now()
					_ = VerifyPassword(tc.hash, "wrong-password")
					verifyDur = min(verifyDur, time.Since(start))

					start = time.Now()
					DummyVerifyPassword("wrong-password")
					dummyDur = min(dummyDur, time.Since(start))
				}
				ratio = float64(verifyDur) / float64(dummyDur)
				if ratio >= 0.75 && ratio <= 1.33 {
					return
				}
				t.Logf("round %d: wrong password=%v unknown address=%v ratio=%.3f, retrying", round+1, verifyDur, dummyDur, ratio)
			}
			t.Fatalf("wrong password answered in %v, unknown address in %v (ratio %.3f, want 0.75-1.33) in all %d rounds", verifyDur, dummyDur, ratio, rounds)
		})
	}
}
