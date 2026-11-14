package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestImap4flagsHasflagAndVariableName is issue #883: the imap4flags extension
// is offered by default, but its hasflag test (RFC 5232 §4) and the optional
// variable name of setflag/addflag/removeflag (§3) did not load, so ManageSieve
// refused a script using them and a stored one never ran. Each script files the
// message into the mailboxes in want only if the flags are what the RFC says.
func TestImap4flagsHasflagAndVariableName(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   []string
	}{
		{
			// RFC 5232 §3.1's example: the internal variable stays empty.
			name: "setflag names a variable",
			script: `require ["imap4flags", "variables", "fileinto"];
setflag "flagvar" "\\Flagged";
if hasflag "\\Flagged" { fileinto "Internal"; }
if hasflag "flagvar" "\\Flagged" { fileinto :flags "${flagvar}" "Archive"; }
`,
			want: []string{"Archive"},
		},
		{
			name: "addflag then hasflag",
			script: `require ["imap4flags", "fileinto"];
addflag "\\Seen";
if hasflag "\\Seen" { fileinto "Read"; }
`,
			want: []string{"Read"},
		},
		{
			// RFC 5232 §3.3's example.
			name: "removeflag names a variable",
			script: `require ["imap4flags", "variables", "relational", "fileinto"];
addflag "flagvar" "$MDNRequired";
if hasflag "flagvar" "$mdnrequired" { fileinto "Requested"; }
removeflag "flagvar" "$MDNRequired";
if hasflag :count "eq" "flagvar" "0" { fileinto "Cleared"; }
`,
			want: []string{"Requested", "Cleared"},
		},
		{
			// RFC 5232 §4's :contains and :count examples.
			name: "hasflag :contains and :count over a variable",
			script: `require ["imap4flags", "variables", "relational", "fileinto"];
set "MyVar" "NonJunk Junk gnus-forward $Forwarded NotJunk JunkRecorded $Junk $NotJunk";
if hasflag :contains "MyVar" ["label", "forward"] { fileinto "Forwarded"; }
if hasflag :contains "MyVar" ["label1", "label2"] { fileinto "Wrong"; }
set "MyFlags" "A B";
if hasflag :count "ge" :comparator "i;ascii-numeric" "MyFlags" "2" { fileinto "Two"; }
`,
			want: []string{"Forwarded", "Two"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// What ManageSieve PUTSCRIPT checks, with the default [sieve]
			// enabled_extensions.
			if err := ValidateScript(tt.script, nil); err != nil {
				t.Fatalf("ValidateScript: %v", err)
			}
			executor, err := NewSieveExecutorWithExtensions(tt.script, EffectiveExtensions(nil))
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
			if !slices.Equal(result.Mailboxes, tt.want) {
				t.Errorf("mailboxes = %q, want %q", result.Mailboxes, tt.want)
			}
		})
	}
}
