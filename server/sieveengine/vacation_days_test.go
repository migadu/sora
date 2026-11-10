package sieveengine

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// RFC 5230 §4.1 requires a minimum of at least one day and permits a
// site-defined maximum. Exercise the actual compiled script and response claim.
func TestVacationDaysBounds(t *testing.T) {
	for _, tc := range []struct {
		days     string
		wantDays int
	}{
		{"0", 1},
		{"1", 1},
		{"7", 7},
		{"365", 365},
		{"366", 365},
		{"106752", 365},
		{"1M", 365},
	} {
		t.Run(tc.days, func(t *testing.T) {
			oracle := newMockVacationOracle()
			script := fmt.Sprintf(`require "vacation"; vacation :days %s "Away";`, tc.days)
			ctx := Context{
				EnvelopeFrom: "sender@example.com",
				EnvelopeTo:   "recipient@example.com",
				Header:       map[string][]string{"From": {"sender@example.com"}},
				Message:      bodyOnly("Hello"),
			}
			evaluate := func() Result {
				t.Helper()
				executor, err := NewSieveExecutorWithOracleAndExtensions(script, 1, oracle, oracle, 10, time.Hour, 0, []string{"vacation"})
				if err != nil {
					t.Fatal(err)
				}
				result, err := executor.Evaluate(context.Background(), ctx)
				if err != nil {
					t.Fatal(err)
				}
				return result
			}
			first := evaluate()
			if first.Vacation == nil {
				t.Fatal("first message should receive a reply")
			}
			if claimed, err := first.Vacation.ClaimResponse(context.Background()); err != nil || !claimed {
				t.Fatalf("claim: claimed=%v err=%v", claimed, err)
			}
			if evaluate().Vacation != nil {
				t.Error("immediate repeat received another reply")
			}
			// Check both sides of the clamped window without waiting in real time.
			for key := range oracle.responses {
				oracle.responses[key] = time.Now().Add(-time.Duration(tc.wantDays)*24*time.Hour + time.Hour)
			}
			if evaluate().Vacation != nil {
				t.Errorf("reply before %d-day window expired", tc.wantDays)
			}
			for key := range oracle.responses {
				oracle.responses[key] = time.Now().Add(-time.Duration(tc.wantDays)*24*time.Hour - time.Hour)
			}
			if evaluate().Vacation == nil {
				t.Errorf("no reply after %d-day window expired", tc.wantDays)
			}
		})
	}
}
