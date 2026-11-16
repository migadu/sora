package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestEnvelopeAuthWithoutAuthenticatedUser is issue #1532: delivery (LMTP and
// the Admin API) has no authenticated user, so the envelope "auth" part has no
// value, but go-sieve tested it as the empty string. `envelope :matches "auth"
// "*"` and `envelope :is "auth" ""` were then true for every message, and a
// rule meant for mail from an authenticated sender fired on all of it.
//
// RFC 5228 §5.4: "Like address and header, this test returns true if any
// combination of the envelope-part list and key-list arguments match and
// returns false otherwise." Pigeonhole and Cyrus yield no "auth" value without
// an authenticated user. The null reverse-path still "is matched against as
// the empty string".
func TestEnvelopeAuthWithoutAuthenticatedUser(t *testing.T) {
	const raw = "From: a@example.com\r\nTo: recipient@example.com\r\nSubject: s\r\n\r\nbody\r\n"

	for _, tc := range []struct {
		name   string
		script string
		from   string
		want   []string
	}{
		{
			name:   "auth matches *",
			script: `require ["envelope", "fileinto"]; if envelope :matches "auth" "*" { fileinto "authenticated"; }`,
			from:   "sender@example.com",
		},
		{
			name:   "auth is the empty key",
			script: `require ["envelope", "fileinto"]; if envelope :is "auth" "" { fileinto "authenticated"; }`,
			from:   "sender@example.com",
		},
		{
			name:   "not auth matches * fires",
			script: `require ["envelope", "fileinto"]; if not envelope :matches "auth" "*" { fileinto "unauthenticated"; }`,
			from:   "sender@example.com",
			want:   []string{"unauthenticated"},
		},
		{
			name:   "from is still tested next to auth",
			script: `require ["envelope", "fileinto"]; if envelope :is ["auth", "from"] "sender@example.com" { fileinto "from"; }`,
			from:   "sender@example.com",
			want:   []string{"from"},
		},
		{
			name:   "the null reverse-path matches the empty key",
			script: `require ["envelope", "fileinto"]; if envelope :is "from" "" { fileinto "bounce"; }`,
			from:   "",
			want:   []string{"bounce"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executor, err := NewSieveExecutorWithExtensions(tc.script, EffectiveExtensions(nil))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			ctx := rawContext(t, raw)
			ctx.EnvelopeFrom = tc.from
			result, err := executor.Evaluate(context.Background(), ctx)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if !slices.Equal(result.Mailboxes, tc.want) {
				t.Errorf("mailboxes = %q, want %q", result.Mailboxes, tc.want)
			}
		})
	}
}
