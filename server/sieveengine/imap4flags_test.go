package sieveengine

import (
	"context"
	"slices"
	"testing"

	"github.com/migadu/sora/helpers"
)

// TestFlagListInAVariable is issue #604. RFC 5232 §2: "A string containing a
// space-separated list of flag names is equivalent to a string list consisting
// of the flags." That holds for a variable's value too. The first addflag of a
// variable holding "\\Seen \\Flagged" reported it as one flag, which delivery
// then dropped as an invalid IMAP keyword, so the message got neither flag.
func TestFlagListInAVariable(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   []string
	}{
		{
			name:   "first addflag",
			script: "require [\"imap4flags\", \"variables\"];\nset \"f\" \"\\\\Seen \\\\Flagged\";\naddflag \"${f}\";\n",
			want:   []string{"\\flagged", "\\seen"},
		},
		{
			name:   "setflag",
			script: "require [\"imap4flags\", \"variables\"];\nset \"f\" \"\\\\Seen \\\\Flagged\";\nsetflag \"${f}\";\n",
			want:   []string{"\\flagged", "\\seen"},
		},
		{
			name:   "addflag after addflag",
			script: "require [\"imap4flags\", \"variables\"];\nset \"f\" \"\\\\Seen \\\\Flagged\";\naddflag \"Work\";\naddflag \"${f}\";\n",
			want:   []string{"\\flagged", "\\seen", "work"},
		},
		{
			// RFC 5232 §2 also: "leading and trailing spaces MUST be ignored".
			// A list amalgamated in a variable starts with a space.
			name:   "amalgamated list",
			script: "require [\"imap4flags\", \"variables\"];\nset \"f\" \"\";\nset \"f\" \"${f} \\\\Seen\";\nset \"f\" \"${f} \\\\Flagged\";\naddflag \"${f}\";\n",
			want:   []string{"\\flagged", "\\seen"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor, err := NewSieveExecutorWithExtensions(tt.script, []string{"imap4flags", "variables"})
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
			got := slices.Sorted(slices.Values(result.Flags))
			if !slices.Equal(got, tt.want) {
				t.Errorf("flags = %q, want %q", got, tt.want)
			}
			// Delivery stores what survives SanitizeFlags; nothing may be dropped.
			raw := helpers.StringsToFlags(result.Flags)
			if dropped := helpers.DroppedFlags(raw, helpers.SanitizeFlags(raw)); len(dropped) > 0 {
				t.Errorf("delivery would drop %q as invalid IMAP keywords", dropped)
			}
		})
	}
}
