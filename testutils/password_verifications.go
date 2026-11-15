package testutils

import (
	"github.com/migadu/sora/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// PasswordVerifications returns how many password verifications this process has
// completed: db.VerifyPassword calls (sora_password_verification_attempts_total, every
// hash type and result) plus db.DummyVerifyPassword calls
// (sora_password_dummy_verifications_total). The difference across a login is the
// number of verifications it ran. A timing oracle test compares that count rather than
// the login's duration against a calibrated verification: CPU contention that eases
// between the calibration and the login makes a correct login look too fast (#782).
//
// The counters are process-wide: take the difference while no other test in the
// process verifies passwords (a test that is not parallel).
func PasswordVerifications() int {
	n := testutil.ToFloat64(metrics.PasswordDummyVerifications)
	ch := make(chan prometheus.Metric)
	go func() {
		metrics.PasswordVerificationAttempts.Collect(ch)
		close(ch)
	}()
	for m := range ch {
		var pb dto.Metric
		if err := m.Write(&pb); err == nil {
			n += pb.GetCounter().GetValue()
		}
	}
	return int(n)
}
