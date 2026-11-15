package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestAddressTestAbsentHeaderMatchesNoKey is issue #1429: go-sieve tested a
// header the message does not have as one empty address, so `address :matches
// "Cc" "*"` was true for a message without a Cc: field and a rule meant to
// catch such messages (`if not address :matches "cc" "*"`) never fired.
//
// RFC 5228 §5.1: "Like envelope and header, this test returns true if any
// combination of the header-list and key-list arguments match and returns
// false otherwise." §5.7: "if the named header is not present, it does not
// match any key, including the empty key."
func TestAddressTestAbsentHeaderMatchesNoKey(t *testing.T) {
	const script = `require "fileinto";
if address :matches "Cc" "*" { fileinto "has-cc"; }
if address :is "Cc" "" { fileinto "empty-cc"; }
if not address :matches "cc" "*" { fileinto "no-cc"; }
`
	executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	for _, tc := range []struct {
		name string
		raw  string
		want []string
	}{
		{
			name: "no Cc field",
			raw:  "From: a@example.com\r\nTo: user@example.com\r\nSubject: s\r\n\r\nbody\r\n",
			want: []string{"no-cc"},
		},
		{
			name: "Cc field",
			raw:  "From: a@example.com\r\nTo: user@example.com\r\nCc: c@example.org\r\nSubject: s\r\n\r\nbody\r\n",
			want: []string{"has-cc"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := executor.Evaluate(context.Background(), rawContext(t, tc.raw))
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if !slices.Equal(result.Mailboxes, tc.want) {
				t.Errorf("mailboxes = %q, want %q", result.Mailboxes, tc.want)
			}
		})
	}
}
