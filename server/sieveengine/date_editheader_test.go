package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestDateSeesHeaderEdits is issue #1589: the date test read the message's
// original fields, so it still found a field that deleteheader removed and
// did not find one that addheader added. RFC 5293 §7: "Tests and actions such
// as "exists", "header", or "vacation" [VACATION] that examine header fields
// MUST examine the current state of a header as modified by any actions that
// have taken place so far."
func TestDateSeesHeaderEdits(t *testing.T) {
	ctx := rawContext(t, "From: a@example.com\r\n"+
		"Date: Tue, 1 Apr 1997 09:06:31 -0800\r\n"+
		"Subject: hello\r\n"+
		"\r\nbody\r\n")

	// editheader is not in the default [sieve] enabled_extensions.
	extensions := EffectiveExtensions(append(slices.Clone(DefaultSieveExtensions), "editheader"))
	for _, tc := range []struct {
		name  string
		pre   string // statements before the test
		test  string
		match bool
	}{
		{name: "original field", test: `date :is "Date" "year" "1997"`, match: true},
		{name: "deleted field", pre: `deleteheader "Date";`, test: `date :is "Date" "year" "1997"`},
		{name: "exists of a deleted field", pre: `deleteheader "Date";`, test: `exists "Date"`},
		{name: "added field", pre: `addheader "X-D" "Tue, 1 Apr 1997 09:06:31 -0800";`,
			test: `date :is "X-D" "year" "1997"`, match: true},
		{name: "field added before the original", pre: `addheader "Date" "Wed, 1 Apr 1998 09:06:31 -0800";`,
			test: `date :is "Date" "year" "1998"`, match: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := `require ["date", "fileinto", "editheader"];
` + tc.pre + `
if ` + tc.test + ` { fileinto "matched"; }
`
			executor, err := NewSieveExecutorWithExtensions(script, extensions)
			if err != nil {
				t.Fatalf("compile: %v\n%s", err, script)
			}
			result, err := executor.Evaluate(context.Background(), ctx)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			var want []string
			if tc.match {
				want = []string{"matched"}
			}
			if !slices.Equal(result.Mailboxes, want) {
				t.Errorf("%s %s: mailboxes = %q, want %q", tc.pre, tc.test, result.Mailboxes, want)
			}
		})
	}
}
