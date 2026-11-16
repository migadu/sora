package sieveengine

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// TestHeaderNameASCIICasemap is issue #1537: header, exists and date tests
// found a header through Unicode case mapping. Go lowers U+212A KELVIN SIGN
// to "k" and U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE to "i", so
// "Key" named the Key header, and editheader's edits were matched with
// strings.EqualFold, which folds U+212A too.
//
// RFC 5228 §2.7: "when a string represents the name of a header, the
// comparator is never user-specified. Header comparisons are always done with
// the "i;ascii-casemap" operator". RFC 4790 §9.2.1: i;ascii-casemap "treats
// US-ASCII letters case-insensitively" and "letters outside ASCII are not
// treated case-insensitively".
func TestHeaderNameASCIICasemap(t *testing.T) {
	const (
		kelvin = "K" // KELVIN SIGN
		dotI   = "İ" // LATIN CAPITAL LETTER I WITH DOT ABOVE
	)
	ctx := rawContext(t, "From: a@example.com\r\n"+
		"Key: x\r\n"+
		"Kickoff: Tue, 1 Apr 1997 09:06:31 -0800\r\n"+
		"Subject: hello\r\n"+
		"\r\nbody\r\n")

	const (
		variable = `, "variables"`
		edit     = `, "editheader"`
	)
	for _, tc := range []struct {
		name    string
		require string // added to the require list
		pre     string // statements before the test
		test    string
		match   bool
	}{
		{name: "header in another ASCII case", test: `header :is "KEY" "x"`, match: true},
		{name: "header with U+212A", test: `header :is "` + kelvin + `ey" "x"`},
		{name: "header with U+0130", test: `header :contains "K` + dotI + `CKOFF" "1997"`},
		{name: "header named by a variable with U+212A", require: variable,
			pre: `set "h" "` + kelvin + `EY";`, test: `header :is "${h}" "x"`},
		{name: "exists in another ASCII case", test: `exists "kEY"`, match: true},
		{name: "exists with U+212A", test: `exists "` + kelvin + `ey"`},
		{name: "exists with U+0130", test: `exists "k` + dotI + `ckoff"`},
		{name: "date in another ASCII case", test: `date :is "KICKOFF" "year" "1997"`, match: true},
		{name: "date with U+212A", test: `date :is "` + kelvin + `ickoff" "year" "1997"`},
		{name: "date with U+0130", test: `date :is "K` + dotI + `ckoff" "year" "1997"`},
		{name: "added field in another ASCII case", require: edit,
			pre: `addheader "X-Kind" "y";`, test: `header :is "x-KIND" "y"`, match: true},
		{name: "added field with U+212A", require: edit,
			pre: `addheader "X-Kind" "y";`, test: `header :is "X-` + kelvin + `ind" "y"`},
		{name: "exists of an added field with U+212A", require: edit,
			pre: `addheader "X-Kind" "y";`, test: `exists "X-` + kelvin + `ind"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := `require ["date", "fileinto"` + tc.require + `];
` + tc.pre + `
if ` + tc.test + ` { fileinto "matched"; }
`
			// editheader is not in the default set.
			exts := DefaultSieveExtensions
			if strings.Contains(tc.require, "editheader") {
				exts = append(slices.Clone(exts), "editheader")
			}
			executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(exts))
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
				t.Errorf("%+q: mailboxes = %q, want %q", tc.test, result.Mailboxes, want)
			}
		})
	}
}
