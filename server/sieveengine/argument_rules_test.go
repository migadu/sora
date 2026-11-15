package sieveengine

import (
	"strings"
	"testing"
)

// TestValidateScriptRefusesUnrequiredComparatorAndLateTag is issue #1057: two
// kinds of script RFC 5228 calls errors loaded, so ManageSieve PUTSCRIPT and the
// User API stored them, and Pigeonhole refuses both.
//
// §2.7.3: "Comparators other than "i;octet" and "i;ascii-casemap" must be
// declared with require [...] If the comparator is not declared with require, it
// is also an error, even if the comparator is supported."
//
// §2.6.2: "Tagged arguments must appear before positional arguments".
func TestValidateScriptRefusesUnrequiredComparatorAndLateTag(t *testing.T) {
	refused := []struct {
		name    string
		script  string
		wantErr string
	}{
		{"unrequired i;ascii-numeric", `if header :is :comparator "i;ascii-numeric" "X-Count" "1" { stop; }`, "comparator-i;ascii-numeric"},
		{"unrequired i;unicode-casemap", `require "relational"; if header :value "eq" :comparator "i;unicode-casemap" "Subject" "x" { stop; }`, "comparator-i;unicode-casemap"},
		{"unrequired comparator in hasflag", `require ["imap4flags", "relational"]; if hasflag :count "ge" :comparator "i;ascii-numeric" "1" { stop; }`, "comparator-i;ascii-numeric"},
		{"tag after a positional argument", `if header "Subject" :is "x" { stop; }`, "after positional arguments"},
		{"tag after the positional arguments", `require ["fileinto", "copy"]; fileinto "Archive" :copy;`, "after positional arguments"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateScript(tc.script, nil)
			if err == nil {
				t.Fatal("ValidateScript accepted the script")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateScript: %v, want an error naming %q", err, tc.wantErr)
			}
		})
	}

	accepted := []string{
		`require "comparator-i;ascii-numeric"; if header :is :comparator "i;ascii-numeric" "X-Count" "1" { stop; }`,
		`require ["relational", "comparator-i;unicode-casemap"]; if header :value "eq" :comparator "i;unicode-casemap" "Subject" "x" { stop; }`,
		`if header :comparator "i;octet" :contains "Subject" "x" { stop; }`,
		`if header :is :comparator "i;ascii-casemap" "Subject" "x" { stop; }`,
		`require ["fileinto", "copy"]; fileinto :copy "Archive";`,
	}
	for _, script := range accepted {
		if err := ValidateScript(script, nil); err != nil {
			t.Errorf("ValidateScript(%s): %v", script, err)
		}
	}
}
