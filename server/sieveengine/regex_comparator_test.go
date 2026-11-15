package sieveengine

import (
	"strings"
	"testing"
)

// TestValidateScriptRefusesRegexWithNumericComparator is issue #1339: :regex
// with the i;ascii-numeric comparator loaded, so ManageSieve PUTSCRIPT, the
// User API and sora-admin stored the script, and the test then failed with
// "match-comparator combination not supported" at every delivery. The same
// comparator with :contains or :matches was refused at load, and Pigeonhole
// refuses it with :regex too.
//
// RFC 5228 §2.7.1: "It is an error to use a comparator with ":contains" or
// ":matches" that is not compatible with it." draft-murchison-sieve-regex §3:
// "The ":regex" match type is subject to the same rules and restrictions as the
// standard match types defined in [SIEVE]."
func TestValidateScriptRefusesRegexWithNumericComparator(t *testing.T) {
	// editheader is not in the default set; the rest are.
	exts := []string{"regex", "imap4flags", "editheader", "comparator-i;ascii-numeric"}

	refused := []struct {
		name   string
		script string
	}{
		{"header :regex", `require ["regex", "comparator-i;ascii-numeric"]; if header :regex :comparator "i;ascii-numeric" "Subject" "^1" { stop; }`},
		{"address :regex", `require ["regex", "comparator-i;ascii-numeric"]; if address :regex :comparator "i;ascii-numeric" "from" "^1" { stop; }`},
		// RFC 5232 §4: "Usage: hasflag [MATCH-TYPE] [COMPARATOR]".
		{"hasflag :regex", `require ["regex", "imap4flags", "comparator-i;ascii-numeric"]; if hasflag :regex :comparator "i;ascii-numeric" "^1" { stop; }`},
		{"header :matches", `require "comparator-i;ascii-numeric"; if header :matches :comparator "i;ascii-numeric" "Subject" "1*" { stop; }`},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateScript(tc.script, exts)
			if err == nil {
				t.Fatal("ValidateScript accepted the script")
			}
			if !strings.Contains(err.Error(), "numeric comparator") {
				t.Fatalf("ValidateScript: %v, want an error naming the numeric comparator", err)
			}
		})
	}

	accepted := []string{
		`require "regex"; if header :regex :comparator "i;octet" "Subject" "^1" { stop; }`,
		`require "regex"; if header :regex "Subject" "^1" { stop; }`,
		`require "comparator-i;ascii-numeric"; if header :is :comparator "i;ascii-numeric" "X-Count" "1" { stop; }`,
		// RFC 5293 §5: "If no value-patterns are specified, then the
		// comparator and match-type options are silently ignored."
		`require ["regex", "editheader", "comparator-i;ascii-numeric"]; deleteheader :regex :comparator "i;ascii-numeric" "X-Count";`,
	}
	for _, script := range accepted {
		if err := ValidateScript(script, exts); err != nil {
			t.Errorf("ValidateScript(%s): %v", script, err)
		}
	}
}
