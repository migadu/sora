package sieveengine

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"
)

// configurableRedirectOracle is a RedirectOracle whose responses can be driven
// per test, and which counts how many times RecordRedirect is invoked so tests
// can assert that a denied redirect is never recorded against the rate limit.
type configurableRedirectOracle struct {
	count     int   // value returned by CountRedirectsSince
	countErr  error // error returned by CountRedirectsSince (simulates DB trouble)
	recordErr error // error returned by RecordRedirect
	recordedN int   // number of RecordRedirect calls observed
}

func (m *configurableRedirectOracle) CountRedirectsSince(ctx context.Context, accountID int64, window time.Duration) (int, error) {
	return m.count, m.countErr
}

func (m *configurableRedirectOracle) RecordRedirect(ctx context.Context, accountID int64) error {
	m.recordedN++
	return m.recordErr
}

// cleanRedirectCtx returns a delivery context that triggers none of the
// suppression rules (real sender, no auto/list headers), so suppression and
// rate-limit tests can isolate the control under test.
func cleanRedirectCtx() Context {
	return Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header: map[string][]string{
			"Subject": {"Regular email"},
			"From":    {"sender@example.com"},
			"To":      {"recipient@example.com"},
		},
		Message: bodyOnly("Test message body"),
	}
}

// evalRedirect builds a single-action `redirect "<target>";` script and evaluates
// it. A denied redirect leaves the implicit keep in place, so the result Action is
// ActionKeep (message retained in INBOX); an allowed redirect yields ActionRedirect.
func evalRedirect(t *testing.T, target string, vacOracle VacationOracle, redirectOracle RedirectOracle, limit int, window time.Duration, ctx Context) Result {
	t.Helper()
	script := fmt.Sprintf("redirect %q;", target)
	exts := []string{"envelope", "fileinto", "redirect", "encoded-character", "imap4flags", "variables", "relational", "vacation", "copy", "regex"}
	executor, err := NewSieveExecutorWithOracleAndExtensions(script, 1, vacOracle, redirectOracle, limit, window, 0, exts)
	if err != nil {
		t.Fatalf("failed to create executor for target %q: %v", target, err)
	}
	res, err := executor.Evaluate(context.Background(), ctx)
	if err != nil {
		t.Fatalf("failed to evaluate redirect to %q: %v", target, err)
	}
	return res
}

// (3) Address validation: malformed / multiple / empty targets must be denied and
// the message kept; a single valid address still relays (no over-blocking).
func TestRedirectTargetValidation(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   Action
	}{
		{"single valid address relays", "forward@example.com", ActionRedirect},
		{"not an address is kept", "not-an-address", ActionKeep},
		{"multiple addresses are kept", "a@b.com, c@d.com", ActionKeep},
		{"empty target is kept", "", ActionKeep},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ro := &configurableRedirectOracle{count: 0}
			res := evalRedirect(t, tt.target, newMockVacationOracle(), ro, 100, time.Hour, cleanRedirectCtx())
			if res.Action != tt.want {
				t.Fatalf("target %q: expected action %s, got %s", tt.target, tt.want, res.Action)
			}
		})
	}
}

// (2) Loop/backscatter suppression: bounces, auto-responders and list mail must
// never be relayed; ordinary mail (and Auto-Submitted: no) still relays.
func TestRedirectSuppression(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(c *Context)
		want   Action
	}{
		{"ordinary mail relays", func(c *Context) {}, ActionRedirect},
		{"null sender is kept", func(c *Context) { c.EnvelopeFrom = "" }, ActionKeep},
		{"auto-submitted is kept", func(c *Context) { c.Header["Auto-Submitted"] = []string{"auto-replied"} }, ActionKeep},
		{"precedence bulk is kept", func(c *Context) { c.Header["Precedence"] = []string{"bulk"} }, ActionKeep},
		{"list-id is kept", func(c *Context) { c.Header["List-Id"] = []string{"<list.example.com>"} }, ActionKeep},
		{"auto-submitted no relays", func(c *Context) { c.Header["Auto-Submitted"] = []string{"no"} }, ActionRedirect},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := cleanRedirectCtx()
			tt.mutate(&ctx)
			ro := &configurableRedirectOracle{count: 0}
			res := evalRedirect(t, "forward@example.com", newMockVacationOracle(), ro, 100, time.Hour, ctx)
			if res.Action != tt.want {
				t.Fatalf("%s: expected action %s, got %s", tt.name, tt.want, res.Action)
			}
		})
	}
}

// (1) Per-account rate limit: under the limit relays and records; at/over the
// limit keeps without recording; a zero limit or nil oracle is unlimited; a DB
// error fails closed to keep. Every kept case proves the no-loss invariant — a
// blocked redirect still lands in INBOX (ActionKeep).
func TestRedirectRateLimit(t *testing.T) {
	t.Run("under limit relays and records once", func(t *testing.T) {
		ro := &configurableRedirectOracle{count: 5}
		res := evalRedirect(t, "forward@example.com", newMockVacationOracle(), ro, 100, time.Hour, cleanRedirectCtx())
		if res.Action != ActionRedirect {
			t.Fatalf("expected redirect under the limit, got %s", res.Action)
		}
		if ro.recordedN != 1 {
			t.Errorf("expected exactly 1 RecordRedirect call, got %d", ro.recordedN)
		}
	})

	t.Run("at the limit is kept without recording", func(t *testing.T) {
		ro := &configurableRedirectOracle{count: 100}
		res := evalRedirect(t, "forward@example.com", newMockVacationOracle(), ro, 100, time.Hour, cleanRedirectCtx())
		if res.Action != ActionKeep {
			t.Fatalf("expected keep when at the limit, got %s", res.Action)
		}
		if ro.recordedN != 0 {
			t.Errorf("a rate-limited redirect must not be recorded, got %d records", ro.recordedN)
		}
	})

	t.Run("over the limit is kept", func(t *testing.T) {
		ro := &configurableRedirectOracle{count: 150}
		res := evalRedirect(t, "forward@example.com", newMockVacationOracle(), ro, 100, time.Hour, cleanRedirectCtx())
		if res.Action != ActionKeep {
			t.Fatalf("expected keep when over the limit, got %s", res.Action)
		}
	})

	t.Run("zero limit disables the check", func(t *testing.T) {
		ro := &configurableRedirectOracle{count: 9999}
		res := evalRedirect(t, "forward@example.com", newMockVacationOracle(), ro, 0, time.Hour, cleanRedirectCtx())
		if res.Action != ActionRedirect {
			t.Fatalf("expected redirect with limit 0 (unlimited), got %s", res.Action)
		}
		if ro.recordedN != 0 {
			t.Errorf("disabled limit must not touch the oracle, got %d records", ro.recordedN)
		}
	})

	t.Run("nil oracle relays unlimited", func(t *testing.T) {
		res := evalRedirect(t, "forward@example.com", newMockVacationOracle(), nil, 100, time.Hour, cleanRedirectCtx())
		if res.Action != ActionRedirect {
			t.Fatalf("expected redirect with nil oracle (unlimited), got %s", res.Action)
		}
	})

	t.Run("count error fails closed to keep", func(t *testing.T) {
		ro := &configurableRedirectOracle{countErr: errors.New("db down")}
		res := evalRedirect(t, "forward@example.com", newMockVacationOracle(), ro, 100, time.Hour, cleanRedirectCtx())
		if res.Action != ActionKeep {
			t.Fatalf("expected keep on DB error (fail-closed-to-keep), got %s", res.Action)
		}
		if ro.recordedN != 0 {
			t.Errorf("a failed rate-limit check must not record, got %d records", ro.recordedN)
		}
	})
}

// evalRedirectScript evaluates script for account 1 against ro with the given limit.
func evalRedirectScript(t *testing.T, script string, ro RedirectOracle, limit int) (Result, error) {
	t.Helper()
	exts := []string{"fileinto", "copy"}
	executor, err := NewSieveExecutorWithOracleAndExtensions(script, 1, newMockVacationOracle(), ro, limit, time.Hour, 0, exts)
	if err != nil {
		t.Fatalf("failed to create executor: %v", err)
	}
	return executor.Evaluate(context.Background(), cleanRedirectCtx())
}

// The rate limit is charged for the redirects delivery is asked to make (#230),
// not for every redirect command the script happened to run.
func TestRedirectRateLimitChargesWhatIsRelayed(t *testing.T) {
	t.Run("redirect cancelled by fileinto is not charged", func(t *testing.T) {
		ro := &configurableRedirectOracle{}
		res, err := evalRedirectScript(t, `require "fileinto"; fileinto "Archive"; redirect "forward@example.com";`, ro, 100)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		// fileinto still takes the message over and the redirect is not relayed.
		if res.Action != ActionFileInto {
			t.Fatalf("expected fileinto, got %s", res.Action)
		}
		if ro.recordedN != 0 {
			t.Errorf("no redirect is relayed, but %d were charged", ro.recordedN)
		}
	})

	t.Run("the same address twice is charged once", func(t *testing.T) {
		ro := &configurableRedirectOracle{}
		res, err := evalRedirectScript(t, `redirect "forward@example.com"; redirect "forward@example.com";`, ro, 100)
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		if res.Action != ActionRedirect {
			t.Fatalf("expected redirect, got %s", res.Action)
		}
		if ro.recordedN != 1 {
			t.Errorf("one address is relayed, but %d redirects were charged", ro.recordedN)
		}
	})

	t.Run("a script that fails is not charged", func(t *testing.T) {
		ro := &configurableRedirectOracle{}
		// go-sieve allows five redirects and fails the script on the sixth; the
		// message is then kept and nothing is relayed.
		var script string
		for i := range 6 {
			script += fmt.Sprintf("redirect \"forward%d@example.com\";\n", i)
		}
		res, err := evalRedirectScript(t, script, ro, 100)
		if err == nil {
			t.Fatalf("expected the script to fail on too many redirects, got %+v", res)
		}
		if res.Action != ActionKeep {
			t.Fatalf("expected keep after a failed script, got %s", res.Action)
		}
		if ro.recordedN != 0 {
			t.Errorf("nothing is relayed, but %d redirects were charged", ro.recordedN)
		}
	})
}

// countingRedirectOracle counts like the database does: every recorded redirect
// shows up in the next count.
type countingRedirectOracle struct{ recorded int }

func (o *countingRedirectOracle) CountRedirectsSince(ctx context.Context, accountID int64, window time.Duration) (int, error) {
	return o.recorded, nil
}

func (o *countingRedirectOracle) RecordRedirect(ctx context.Context, accountID int64) error {
	o.recorded++
	return nil
}

// A script may redirect to several addresses (RFC 5228 §2.10.4); the result
// carries each one once, in script order (#230).
func TestMultipleRedirects(t *testing.T) {
	tests := []struct {
		name         string
		script       string
		limit        int
		want         []string
		wantCopy     bool
		wantRecorded int
	}{
		{
			name:         "every address is carried",
			script:       `redirect "one@example.com"; redirect "two@example.org"; redirect "three@example.net";`,
			limit:        100,
			want:         []string{"one@example.com", "two@example.org", "three@example.net"},
			wantRecorded: 3,
		},
		{
			name:         "copy keeps the message too",
			script:       `require "copy"; redirect :copy "one@example.com"; redirect :copy "two@example.org";`,
			limit:        100,
			want:         []string{"one@example.com", "two@example.org"},
			wantCopy:     true,
			wantRecorded: 2,
		},
		{
			name:         "one redirect without copy cancels the keep",
			script:       `require "copy"; redirect :copy "one@example.com"; redirect "two@example.org";`,
			limit:        100,
			want:         []string{"one@example.com", "two@example.org"},
			wantRecorded: 2,
		},
		{
			name:         "a repeated address is carried once",
			script:       `redirect "one@example.com"; redirect "two@example.org"; redirect "one@example.com";`,
			limit:        100,
			want:         []string{"one@example.com", "two@example.org"},
			wantRecorded: 2,
		},
		{
			name:         "a malformed address does not stop the others",
			script:       `redirect "not-an-address"; redirect "two@example.org";`,
			limit:        100,
			want:         []string{"two@example.org"},
			wantRecorded: 1,
		},
		{
			name:         "the rate limit cuts off within one message",
			script:       `redirect "one@example.com"; redirect "two@example.org"; redirect "three@example.net";`,
			limit:        2,
			want:         []string{"one@example.com", "two@example.org"},
			wantRecorded: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ro := &countingRedirectOracle{}
			res, err := evalRedirectScript(t, tt.script, ro, tt.limit)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if res.Action != ActionRedirect {
				t.Fatalf("expected redirect, got %s", res.Action)
			}
			if !slices.Equal(res.RedirectTo, tt.want) {
				t.Errorf("RedirectTo = %v, want %v", res.RedirectTo, tt.want)
			}
			if res.Copy != tt.wantCopy {
				t.Errorf("Copy = %v, want %v", res.Copy, tt.wantCopy)
			}
			if ro.recorded != tt.wantRecorded {
				t.Errorf("charged %d redirects, want %d", ro.recorded, tt.wantRecorded)
			}
		})
	}
}
