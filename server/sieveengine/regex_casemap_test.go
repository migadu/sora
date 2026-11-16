package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestRegexCaseMap is issue #1338: under the default comparator,
// i;ascii-casemap, a :regex match lowercased the header and left the pattern
// as written, so a pattern with an upper-case letter never matched and the
// match variables held the lowercased header. RFC 5228 §2.7.3: i;ascii-casemap
// "treats uppercase and lowercase characters in the US-ASCII subset of UTF-8 as
// the same"; Pigeonhole compiles the pattern with REG_ICASE and matches it
// against the header as it is (mcht-regex.c).
func TestRegexCaseMap(t *testing.T) {
	tests := []struct {
		name    string
		script  string
		subject string
		want    []string
	}{
		{
			name:    "upper-case pattern",
			script:  `require ["regex", "fileinto"]; if header :regex "Subject" "^URGENT" { fileinto "Hit"; }`,
			subject: "URGENT Stuff",
			want:    []string{"Hit"},
		},
		{
			name:    "upper-case pattern, lower-case header",
			script:  `require ["regex", "fileinto"]; if header :regex "Subject" "^URGENT" { fileinto "Hit"; }`,
			subject: "urgent stuff",
			want:    []string{"Hit"},
		},
		{
			name:    "match variable holds the header's text",
			script:  `require ["regex", "fileinto", "variables"]; if header :regex "Subject" "^(u.*)$" { fileinto "Hit-${1}"; }`,
			subject: "URGENT Stuff",
			want:    []string{"Hit-URGENT Stuff"},
		},
		{
			name:    "negated bracket excludes both cases",
			script:  `require ["regex", "fileinto"]; if header :regex "Subject" "^[^A-Z]" { fileinto "Hit"; }`,
			subject: "urgent stuff",
			want:    nil,
		},
		{
			name:    "i;octet stays case-sensitive",
			script:  `require ["regex", "fileinto"]; if header :comparator "i;octet" :regex "Subject" "^URGENT" { fileinto "Hit"; }`,
			subject: "urgent stuff",
			want:    nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// What ManageSieve PUTSCRIPT checks, with the default [sieve] enabled_extensions.
			if err := ValidateScript(tc.script, nil); err != nil {
				t.Fatalf("ValidateScript: %v", err)
			}
			executor, err := NewSieveExecutorWithExtensions(tc.script, EffectiveExtensions(nil))
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			result, err := executor.Evaluate(context.Background(), Context{
				EnvelopeFrom: "sender@example.com",
				EnvelopeTo:   "user@example.com",
				Header:       map[string][]string{"Subject": {tc.subject}, "From": {"sender@example.com"}},
				Message:      bodyOnly("body"),
			})
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if !slices.Equal(result.Mailboxes, tc.want) {
				t.Errorf("Subject: %s: mailboxes = %q, want %q", tc.subject, result.Mailboxes, tc.want)
			}
		})
	}
}
