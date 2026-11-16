package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestVariablesExpandedOnce is issue #1525: a string with a variable
// reference is evaluated in exactly one pass.
//
// RFC 5229 §3: "When a string is evaluated, substrings matching variable-ref
// SHALL be replaced by the value of variable-name. Only one pass through the
// string SHALL be done." A match key was expanded twice, so a Subject copied
// into a variable was read as references again (and one naming an unknown
// namespace panicked).
//
// RFC 5173 §6: "if the extension is present, variable references in the key
// strings or content type strings are evaluated as described in this
// document." The body test's :content list was not expanded at all.
func TestVariablesExpandedOnce(t *testing.T) {
	tests := []struct {
		name   string
		script string
		msg    string
		want   []string
	}{
		{
			name: "key copied from the subject",
			script: `require ["variables", "fileinto"];
set "b" "SECRET";
if header :matches "subject" "*" { set "s" "${1}"; }
if header :is "subject" "${s}" { fileinto "same"; }
`,
			msg:  "From: a@example.com\r\nSubject: ${b}\r\n\r\nbody\r\n",
			want: []string{"same"},
		},
		{
			name: "key holding an unknown namespace reference",
			script: `require ["variables", "fileinto"];
if header :matches "subject" "*" { set "s" "${1}"; }
if header :is "subject" "${s}" { fileinto "same"; }
`,
			msg:  "From: a@example.com\r\nSubject: ${nosuch.name}\r\n\r\nbody\r\n",
			want: []string{"same"},
		},
		{
			name: "body :content type from a variable",
			script: `require ["body", "variables", "fileinto"];
set "t" "text";
if body :content "${t}" :contains "Hello" { fileinto "hello"; }
`,
			msg:  "From: a@example.com\r\nSubject: s\r\nContent-Type: text/plain\r\n\r\nHello world.\r\n",
			want: []string{"hello"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateScript(tc.script, nil); err != nil {
				t.Fatalf("ValidateScript: %v", err)
			}
			executor, err := NewSieveExecutorWithExtensions(tc.script, EffectiveExtensions(nil))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			result, err := executor.Evaluate(context.Background(), rawContext(t, tc.msg))
			if err != nil {
				t.Fatalf("evaluate: %.200v", err)
			}
			if !slices.Equal(result.Mailboxes, tc.want) {
				t.Errorf("action = %s, mailboxes = %q, want %q", result.Action, result.Mailboxes, tc.want)
			}
		})
	}
}
