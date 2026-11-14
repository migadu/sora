package server

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// seriesWith returns the series of family whose labels include all of labels.
func seriesWith(t *testing.T, family string, labels map[string]string) []*dto.Metric {
	t.Helper()
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var out []*dto.Metric
	for _, mf := range mfs {
		if mf.GetName() != family {
			continue
		}
	series:
		for _, m := range mf.GetMetric() {
			for name, value := range labels {
				found := false
				for _, lp := range m.GetLabel() {
					if lp.GetName() == name && lp.GetValue() == value {
						found = true
					}
				}
				if !found {
					continue series
				}
			}
			out = append(out, m)
		}
	}
	return out
}

// TestSessionLockMetricsUseLowercaseProtocol: MutexTimeoutHelper times the lock on a
// session's own state, not a mailbox lock, so its metrics are named after the session.
// Their protocol label is lowercase like every other metric's ("imap", not "IMAP"),
// whatever the caller passes.
func TestSessionLockMetricsUseLowercaseProtocol(t *testing.T) {
	var mu sync.RWMutex
	h := NewMutexTimeoutHelper(&mu, context.Background(), "IMAP", nil)

	if ok, release := h.AcquireWriteLockWithTimeout(context.Background()); !ok {
		t.Fatal("uncontended write lock not acquired")
	} else {
		release()
	}
	if ok, release := h.AcquireReadLockWithTimeout(context.Background()); !ok {
		t.Fatal("uncontended read lock not acquired")
	} else {
		release()
	}
	// A read lock given up while another holder keeps the write lock.
	mu.Lock()
	cancelled, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	ok, release := h.AcquireReadLockWithTimeout(cancelled)
	release()
	cancel()
	mu.Unlock()
	if ok {
		t.Fatal("contended read lock acquired after its context ended")
	}

	for _, c := range []struct {
		family string
		labels map[string]string
	}{
		{"sora_session_lock_duration_seconds", map[string]string{"protocol": "imap", "lock_type": "write", "result": "success"}},
		{"sora_session_lock_duration_seconds", map[string]string{"protocol": "imap", "lock_type": "read", "result": "success"}},
		{"sora_session_lock_duration_seconds", map[string]string{"protocol": "imap", "lock_type": "read", "result": "timeout"}},
		{"sora_session_lock_timeouts_total", map[string]string{"protocol": "imap", "lock_type": "read"}},
	} {
		if len(seriesWith(t, c.family, c.labels)) == 0 {
			t.Errorf("no %s series with %v", c.family, c.labels)
		}
	}
	for _, family := range []string{"sora_session_lock_duration_seconds", "sora_session_lock_timeouts_total", "sora_mailbox_lock_duration_seconds", "sora_mailbox_lock_timeouts_total"} {
		if got := seriesWith(t, family, map[string]string{"protocol": "IMAP"}); len(got) > 0 {
			t.Errorf("%s has %d series with protocol=\"IMAP\"", family, len(got))
		}
	}
}

// TestSearchRateLimiterProtocolLabelIsLowercase: a refusal is counted in
// sora_protocol_errors_total under the same lowercase protocol as the protocol's
// other errors, whatever the caller passes.
func TestSearchRateLimiterProtocolLabelIsLowercase(t *testing.T) {
	limiter := NewSearchRateLimiter("IMAP", 1, time.Hour, 0)
	t.Cleanup(limiter.Stop)

	count := func(protocol string) float64 {
		var sum float64
		for _, m := range seriesWith(t, "sora_protocol_errors_total", map[string]string{
			"protocol": protocol, "command": "SEARCH", "error_type": "rate_limited",
		}) {
			sum += m.GetCounter().GetValue()
		}
		return sum
	}
	lower0, upper0 := count("imap"), count("IMAP")

	refused := 0
	for i := 0; i < 3; i++ {
		if limiter.CanSearch(context.Background(), 294) != nil {
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("no search refused; the test does not exercise the limit")
	}
	if d := count("imap") - lower0; d != float64(refused) {
		t.Errorf(`protocol="imap" grew by %v after %d refusals, want %d`, d, refused, refused)
	}
	if d := count("IMAP") - upper0; d != 0 {
		t.Errorf(`protocol="IMAP" grew by %v, want 0`, d)
	}
}
