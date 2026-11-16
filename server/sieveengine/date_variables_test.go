package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestDateZoneAndDatePartFromVariables is issue #1383: a variable in the :zone
// or the date-part of the date test refused the script ("date: invalid zone
// format: ${z}"). RFC 5229 §3: "When a string is evaluated, substrings
// matching variable-ref SHALL be replaced by the value of variable-name."
func TestDateZoneAndDatePartFromVariables(t *testing.T) {
	const script = `require ["date", "variables", "fileinto"];
set "z" "-0700";
set "p" "hour";
if date :zone "${z}" "date" "${p}" "02" { fileinto "hour02"; }
if currentdate :zone "${z}" "zone" "-0700" { fileinto "now"; }
`
	// What ManageSieve PUTSCRIPT checks, with the default [sieve] enabled_extensions.
	if err := ValidateScript(script, nil); err != nil {
		t.Fatalf("ValidateScript: %v", err)
	}
	executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, tc := range []struct {
		date string
		want []string
	}{
		{"Wed, 17 Jul 1996 02:23:25 -0700", []string{"hour02", "now"}},
		{"Wed, 17 Jul 1996 02:23:25 +0000", []string{"now"}},
	} {
		result, err := executor.Evaluate(context.Background(), Context{
			EnvelopeFrom: "sender@example.com",
			EnvelopeTo:   "user@example.com",
			Header:       map[string][]string{"Date": {tc.date}, "From": {"sender@example.com"}},
			Message:      bodyOnly("body"),
		})
		if err != nil {
			t.Fatalf("%q: evaluate: %v", tc.date, err)
		}
		if !slices.Equal(result.Mailboxes, tc.want) {
			t.Errorf("Date: %s: mailboxes = %q, want %q", tc.date, result.Mailboxes, tc.want)
		}
	}
}
