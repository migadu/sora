package sieveengine

import (
	"strings"
	"testing"
)

// TestValidateScriptRefusesTagWithoutValue is issue #1224: a tagged argument
// that takes a value but ends the argument list loaded as if it were absent,
// so ManageSieve PUTSCRIPT, the User API and sora-admin stored such a script,
// and Pigeonhole refuses it ("requires a string list as parameter, but no
// parameters were found").
//
// RFC 5232 §5: "Usage:   ":flags" <list-of-flags: string-list>". RFC 5703 §3:
// "Usage:  foreverypart [":name" string] block" and "Usage:  break [":name"
// string];".
func TestValidateScriptRefusesTagWithoutValue(t *testing.T) {
	refused := []struct {
		name    string
		script  string
		wantErr string
	}{
		{"keep :flags", `require "imap4flags"; keep :flags;`, ":flags requires a value"},
		{"foreverypart :name", `require "foreverypart"; foreverypart :name { }`, ":name requires a value"},
		{"break :name", `require "foreverypart"; foreverypart { break :name; }`, ":name requires a value"},
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
		`require "imap4flags"; keep :flags "\\Seen";`,
		`require "imap4flags"; keep;`,
		`require "foreverypart"; foreverypart :name "outer" { break :name "outer"; }`,
		`require "foreverypart"; foreverypart { break; }`,
	}
	for _, script := range accepted {
		if err := ValidateScript(script, nil); err != nil {
			t.Errorf("ValidateScript(%s): %v", script, err)
		}
	}
}
