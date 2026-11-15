package sieveengine

import (
	"context"
	"testing"
)

// TestAddressHeaderNamedByVariable is issue #1430: an address test on a header
// named by a variable skipped the header when the variable's value was not
// lower case, so `set "h" "From"; address :is "${h}" ...` never matched while
// `address :is "From" ...` did.
//
// RFC 5228 §2.7.3: "when a string represents the name of a header, the
// comparator is never user-specified. Header comparisons are always done with
// the "i;ascii-casemap" operator". RFC 5229 §3: "When a string is evaluated,
// substrings matching variable-ref SHALL be replaced by the value of
// variable-name."
func TestAddressHeaderNamedByVariable(t *testing.T) {
	ctx := rawContext(t, "From: a@example.com\r\nSubject: hello\r\n\r\nbody\r\n")
	for _, name := range []string{"from", "From", "FROM"} {
		t.Run(name, func(t *testing.T) {
			script := `require ["variables", "fileinto"];
set "h" "` + name + `";
if address :is "${h}" "a@example.com" { fileinto "matched"; }
`
			executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			result, err := executor.Evaluate(context.Background(), ctx)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if result.Action != ActionFileInto || len(result.Mailboxes) != 1 || result.Mailboxes[0] != "matched" {
				t.Errorf("action = %s, mailboxes = %q, want fileinto [\"matched\"]", result.Action, result.Mailboxes)
			}
		})
	}
}
