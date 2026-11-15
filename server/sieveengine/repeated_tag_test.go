package sieveengine

import (
	"strings"
	"testing"
)

// TestValidateScriptRefusesRepeatedTag is issue #1238: a command that gives the
// same tagged argument twice loaded (the last value winning), so ManageSieve
// PUTSCRIPT, the User API and sora-admin stored it; Pigeonhole refuses it.
//
// RFC 5228 §2.6: "It is an error for a script, on a single command, to use
// conflicting arguments or to use a tagged or optional argument more than once."
func TestValidateScriptRefusesRepeatedTag(t *testing.T) {
	refused := []struct {
		name    string
		script  string
		wantErr string
	}{
		{"header :comparator", `if header :comparator "i;octet" :comparator "i;ascii-casemap" "Subject" "x" { stop; }`, ":comparator given more than once"},
		{"vacation :days", `require "vacation"; vacation :days 1 :days 2 "away";`, ":days given more than once"},
		{"vacation :subject", `require "vacation"; vacation :subject "a" :subject "b" "away";`, ":subject given more than once"},
		{"fileinto :copy", `require ["fileinto", "copy"]; fileinto :copy :copy "Archive";`, ":copy given more than once"},
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
		`if header :comparator "i;octet" :is "Subject" "x" { stop; }`,
		`require "vacation"; vacation :days 1 :subject "a" "away";`,
		`require ["fileinto", "copy"]; fileinto :copy "Archive"; fileinto :copy "Old";`,
	}
	for _, script := range accepted {
		if err := ValidateScript(script, nil); err != nil {
			t.Errorf("ValidateScript(%s): %v", script, err)
		}
	}
}
