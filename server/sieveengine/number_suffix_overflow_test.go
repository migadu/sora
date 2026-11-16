package sieveengine

import (
	"context"
	"math"
	"strconv"
	"testing"
)

// TestNumberSuffixOverflowRefused is issue #1448: go-sieve multiplied a number
// by its K/M/G suffix without a range check, so `size :over 9007199254740992K`
// (2^63) wrapped to a negative bound and filed every message, while a number
// too large without a suffix was refused at compile time.
//
// RFC 5228 §2.4.1: "K" is 2^10, "M" 2^20 and "G" 2^30 "times the value of the
// number", and "Only non-negative integers are permitted by this
// specification."
func TestNumberSuffixOverflowRefused(t *testing.T) {
	const raw = "Subject: s\r\n\r\nshort body\r\n"

	for _, script := range []string{
		`require "fileinto"; if size :over 9007199254740992K { fileinto "over"; }`,
		`require "fileinto"; if size :over 18014398509481985K { fileinto "over"; }`, // wraps to 1024
		`require "fileinto"; if size :over 8589934592G { fileinto "over"; }`,
		`require "fileinto"; if size :over 99999999999999999999 { fileinto "over"; }`, // no suffix: already refused
	} {
		t.Run(script, func(t *testing.T) {
			if err := ValidateScript(script, nil); err == nil {
				t.Error("ValidateScript accepted a number that does not fit with its suffix")
			}
			executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
			if err == nil {
				result, evalErr := executor.Evaluate(context.Background(), rawContext(t, raw))
				t.Fatalf("compiled; evaluate = %q, %v; want a compile error", result.Mailboxes, evalErr)
			}
		})
	}

	// The largest number that still fits with the suffix keeps its exact value.
	script := `require "fileinto"; if size :over ` + strconv.Itoa(math.MaxInt/1024) + `K { fileinto "over"; } else { fileinto "under"; }`
	executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile %q: %v", script, err)
	}
	result, err := executor.Evaluate(context.Background(), rawContext(t, raw))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(result.Mailboxes) != 1 || result.Mailboxes[0] != "under" {
		t.Errorf("mailboxes = %q, want [\"under\"]", result.Mailboxes)
	}
}
