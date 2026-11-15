package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestRepeatedFileintoTarget is issue #603: a mailbox filed into twice is stored
// in once (RFC 5228 §2.10.3), but the repeat still cancels the implicit keep
// unless it has :copy (RFC 5228 §2.10.2, RFC 3894 §3), and its :create still
// creates the mailbox (RFC 5490 §3.2), whichever of the two comes first.
func TestRepeatedFileintoTarget(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   []Destination
	}{
		{
			name:   ":copy then without",
			script: "require [\"fileinto\", \"copy\"];\nfileinto :copy \"Archive\";\nfileinto \"Archive\";\n",
			want:   []Destination{{Mailbox: "Archive"}},
		},
		{
			name:   "without then :copy",
			script: "require [\"fileinto\", \"copy\"];\nfileinto \"Archive\";\nfileinto :copy \"Archive\";\n",
			want:   []Destination{{Mailbox: "Archive"}},
		},
		{
			name:   ":copy twice",
			script: "require [\"fileinto\", \"copy\"];\nfileinto :copy \"Archive\";\nfileinto :copy \"Archive\";\n",
			want:   []Destination{{Mailbox: "Archive"}, {Mailbox: "INBOX"}},
		},
		{
			name:   "without then :create",
			script: "require [\"fileinto\", \"mailbox\"];\nfileinto \"Projects\";\nfileinto :create \"Projects\";\n",
			want:   []Destination{{Mailbox: "Projects", Create: true}},
		},
		{
			name:   ":create then without",
			script: "require [\"fileinto\", \"mailbox\"];\nfileinto :create \"Projects\";\nfileinto \"Projects\";\n",
			want:   []Destination{{Mailbox: "Projects", Create: true}},
		},
		{
			name:   ":copy then :create",
			script: "require [\"fileinto\", \"copy\", \"mailbox\"];\nfileinto :copy \"Projects\";\nfileinto :create \"Projects\";\n",
			want:   []Destination{{Mailbox: "Projects", Create: true}},
		},
		{
			name:   "explicit keep before repeated target",
			script: `require ["fileinto", "copy"]; keep; fileinto :copy "Archive"; fileinto "Archive";`,
			want:   []Destination{{Mailbox: "Archive"}, {Mailbox: "INBOX"}},
		},
		{
			name:   "discard after repeated copies",
			script: `require ["fileinto", "copy"]; fileinto :copy "Archive"; fileinto :copy "Archive"; discard;`,
			want:   []Destination{{Mailbox: "Archive"}},
		},
		{
			name:   "repeat through a variable",
			script: `require ["fileinto", "copy", "variables"]; set "box" "Archive"; fileinto :copy "Archive"; fileinto "${box}";`,
			want:   []Destination{{Mailbox: "Archive"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor, err := NewSieveExecutorWithExtensions(tt.script, []string{"fileinto", "copy", "mailbox", "variables"})
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			result, err := executor.Evaluate(context.Background(), Context{
				EnvelopeFrom: "sender@example.com",
				EnvelopeTo:   "user@example.com",
				Header:       map[string][]string{"Subject": {"Test"}, "From": {"sender@example.com"}},
				Message:      bodyOnly("body"),
			})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if got := result.Destinations(false); !slices.Equal(got, tt.want) {
				t.Errorf("Destinations = %v, want %v (Mailboxes %v, CreateMailboxes %v, Copy %v)",
					got, tt.want, result.Mailboxes, result.CreateMailboxes, result.Copy)
			}
		})
	}
}
