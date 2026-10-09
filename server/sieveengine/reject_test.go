package sieveengine

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func evaluateForReject(t *testing.T, script string) (Result, error) {
	t.Helper()
	oracle := newMockVacationOracle()
	executor, err := NewSieveExecutorWithOracleAndExtensions(script, 1, oracle, oracle, 10, time.Hour, 0, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("default extensions refuse the script: %v", err)
	}
	return executor.Evaluate(context.Background(), Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "recipient@example.com",
		Header: map[string][]string{
			"Subject": {"Buy now"},
			"From":    {"sender@example.com"},
		},
		Message: bodyOnly("Test body"),
	})
}

// A script requiring reject used to fail to compile, which dropped every other
// rule in it. reject and ereject now compile with the default extensions and
// are delivered as a discard: no bounce, DSN or MDN.
func TestRejectIsDiscard(t *testing.T) {
	cases := []struct {
		name   string
		script string
		reason string
	}{
		{"reject", `require "reject"; reject "go away";`, "go away"},
		{"ereject", `require "ereject"; ereject "go away";`, "go away"},
		{"conditional, with the rest of the script", `require ["fileinto", "reject"];
if header :contains "subject" "lottery" { fileinto "Junk"; stop; }
if header :contains "subject" "buy" { reject "no ads"; stop; }`, "no ads"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := evaluateForReject(t, tc.script)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if result.Action != ActionDiscard || !result.Rejected || result.RejectReason != tc.reason {
				t.Fatalf("got action=%s rejected=%v reason=%q, want discard true %q",
					result.Action, result.Rejected, result.RejectReason, tc.reason)
			}
		})
	}
}

// The other rules of a script that requires reject run as before.
func TestRejectScriptOtherRulesRun(t *testing.T) {
	result, err := evaluateForReject(t, `require ["fileinto", "reject"];
if header :contains "subject" "buy" { fileinto "Ads"; stop; }
reject "no";`)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Action != ActionFileInto || result.Mailbox != "Ads" || result.Rejected {
		t.Fatalf("got action=%s mailbox=%q rejected=%v, want fileinto Ads", result.Action, result.Mailbox, result.Rejected)
	}
}

// A plain discard is not reported as a reject.
func TestDiscardIsNotRejected(t *testing.T) {
	result, err := evaluateForReject(t, `discard;`)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.Action != ActionDiscard || result.Rejected {
		t.Fatalf("got action=%s rejected=%v, want discard false", result.Action, result.Rejected)
	}
}

// RFC 5429 §2.4 conflicts are runtime errors; delivery then keeps the message
// (LMTP falls back to the default script's result), as Pigeonhole does.
func TestRejectConflictKeeps(t *testing.T) {
	for _, script := range []string{
		`require ["reject", "fileinto"]; fileinto "Junk"; reject "no";`,
		`require ["reject", "vacation"]; reject "no"; vacation "away";`,
		`require "reject"; reject "a"; reject "b";`,
	} {
		result, err := evaluateForReject(t, script)
		if err == nil || !strings.Contains(err.Error(), "reject") {
			t.Fatalf("%s: err = %v, want a reject conflict", script, err)
		}
		if result.Action != ActionKeep {
			t.Fatalf("%s: action = %s, want keep", script, result.Action)
		}
	}
}

// The log line names the action and bounds the script-controlled reason.
func TestRejectLogFields(t *testing.T) {
	action, reason := (Result{Rejected: true, RejectReason: "no"}).RejectLogFields()
	if action != "reject" || reason != "no" {
		t.Fatalf("got %q %q, want reject no", action, reason)
	}
	action, _ = (Result{Rejected: true, RejectExtended: true}).RejectLogFields()
	if action != "ereject" {
		t.Fatalf("got %q, want ereject", action)
	}
	// 255 ASCII bytes then a 2-byte rune straddling the cut: the cut moves back to
	// the rune start, so the logged reason is valid UTF-8 and bounded.
	long := strings.Repeat("a", maxLoggedRejectReason-1) + "é" + strings.Repeat("b", 100)
	_, reason = (Result{Rejected: true, RejectReason: long}).RejectLogFields()
	if !strings.HasSuffix(reason, "...") || len(reason) > maxLoggedRejectReason+3 || !utf8.ValidString(reason) {
		t.Fatalf("reason len=%d valid=%v suffix=%q", len(reason), utf8.ValidString(reason), reason[len(reason)-6:])
	}
	if strings.TrimSuffix(reason, "...") != strings.Repeat("a", maxLoggedRejectReason-1) {
		t.Fatalf("cut landed inside the rune: %q", reason[len(reason)-8:])
	}
}
