package sieveengine

import (
	"context"
	"strings"
	"testing"
	"time"
)

// inputCap mirrors interp.DefaultRegexLimits.MaxInputLength in the go-sieve
// fork: the bounded :matches/:regex executor truncates match input to this
// length so a single test cannot run unbounded.
const inputCap = 256 * 1024

// TestMatchesTruncatesLargeBody is the end-to-end regression for security-audit
// item M12. A `body :matches` against a multi-hundred-KB body must be bounded:
// content beyond the input cap is truncated away (a needle past the cap does
// NOT match), and the evaluation returns promptly instead of scanning the whole
// body. The 2s engine deadline is also threaded into the match path now.
func TestMatchesTruncatesLargeBody(t *testing.T) {
	const script = `require ["body", "fileinto"];
if body :raw :matches "*NEEDLE*" {
	fileinto "Matched";
}
`
	executor, err := NewSieveExecutorWithExtensions(script, []string{"body", "fileinto", "variables", "regex"})
	if err != nil {
		t.Fatalf("create executor: %v", err)
	}

	bodyWithNeedleAt := func(offset int) string {
		var sb strings.Builder
		sb.Grow(offset + len("NEEDLE") + 4096)
		sb.WriteString(strings.Repeat("x", offset))
		sb.WriteString("NEEDLE")
		sb.WriteString(strings.Repeat("y", 4096))
		return sb.String()
	}

	eval := func(body string) (Result, time.Duration) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		start := time.Now()
		res, err := executor.Evaluate(ctx, Context{
			EnvelopeFrom: "sender@example.com",
			EnvelopeTo:   "recipient@example.com",
			Header:       map[string][]string{"Subject": {"hi"}},
			Body:         body,
		})
		if err != nil {
			t.Fatalf("evaluate: %v", err)
		}
		return res, time.Since(start)
	}

	// Needle well within the cap -> matched -> fileinto "Matched".
	if res, _ := eval(bodyWithNeedleAt(1024)); res.Action != ActionFileInto || res.Mailbox != "Matched" {
		t.Fatalf("needle within cap: expected fileinto Matched, got action=%q mailbox=%q", res.Action, res.Mailbox)
	}

	// Needle planted beyond the cap -> truncated away -> no match -> implicit
	// keep, and the evaluation stays well under the 2s script budget.
	res, elapsed := eval(bodyWithNeedleAt(inputCap + 50_000))
	if res.Action != ActionKeep {
		t.Fatalf("needle past cap: expected keep (truncated, no match), got action=%q mailbox=%q", res.Action, res.Mailbox)
	}
	if elapsed > time.Second {
		t.Errorf("bounded match took too long (%v); expected sub-second after truncation", elapsed)
	}
}

// TestMatchesCaptureStillWorks guards that bounding :matches did not change its
// wildcard capture-variable semantics for normal (small-input) header tests.
func TestMatchesCaptureStillWorks(t *testing.T) {
	const script = `require ["variables", "fileinto"];
if header :matches "Subject" "ticket-*" {
	fileinto "Tickets/${1}";
}
`
	executor, err := NewSieveExecutorWithExtensions(script, []string{"variables", "fileinto"})
	if err != nil {
		t.Fatalf("create executor: %v", err)
	}

	res, err := executor.Evaluate(context.Background(), Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header:       map[string][]string{"Subject": {"ticket-42"}},
		Body:         "body",
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if res.Action != ActionFileInto || res.Mailbox != "Tickets/42" {
		t.Fatalf("expected fileinto Tickets/42 from captured wildcard, got action=%q mailbox=%q", res.Action, res.Mailbox)
	}
}
