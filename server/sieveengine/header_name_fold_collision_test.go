package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestHeaderNamesFoldingToOneName is issue #1590: go-message keys a field by
// textproto.CanonicalMIMEHeaderKey, which returns a name holding a byte that is
// not an RFC 7230 token character, such as "(", as written. "X(a" and "x(A" are
// then two keys of the header map, and building the script's map assigned the
// second one to fold to "x(a" over the first, so one field's values were lost
// (which one depended on map order).
//
// Such bytes are valid in a field name (RFC 5322 §3.6.8: ftext = %d33-57 /
// %d59-126), and RFC 5228 §2.7: "Header comparisons are always done with the
// "i;ascii-casemap" operator", so "x(a" names both fields. RFC 5260 §6 counts
// :index from "the first named header field", and §4 dates "only the first
// field that is found", so the fields must also keep their message order.
func TestHeaderNamesFoldingToOneName(t *testing.T) {
	parsed := rawContext(t, "From: a@example.com\r\n"+
		"X(a: 1\r\n"+
		"Subject: hello\r\n"+
		"x(A: 2\r\n"+
		"X(d: Tue, 1 Apr 1997 09:06:31 -0800\r\n"+
		"x(D: Wed, 1 Apr 1998 09:06:31 -0800\r\n"+
		"\r\nbody\r\n")
	// A map a caller built itself, with the two spellings as separate keys.
	built := parsed
	built.Header = map[string][]string{
		"From": {"a@example.com"},
		"X(a":  {"1"},
		"x(A":  {"2"},
	}

	for _, tc := range []struct {
		name  string
		ctx   Context
		test  string
		match bool
	}{
		{name: "built map, first spelling", ctx: built, test: `header :is "x(a" "1"`, match: true},
		{name: "built map, second spelling", ctx: built, test: `header :is "X(A" "2"`, match: true},
		{name: "built map, count", ctx: built, test: `header :count "eq" "x(a" "2"`, match: true},

		{name: "first spelling", ctx: parsed, test: `header :is "x(a" "1"`, match: true},
		{name: "second spelling", ctx: parsed, test: `header :is "x(a" "2"`, match: true},
		{name: "count", ctx: parsed, test: `header :count "eq" "x(a" "2"`, match: true},
		{name: "index 1 is the first field", ctx: parsed, test: `header :index 1 "x(a" "1"`, match: true},
		{name: "index 2 is the second field", ctx: parsed, test: `header :index 2 "x(a" "2"`, match: true},
		{name: "index 1 last is the second field", ctx: parsed, test: `header :index 1 :last "x(a" "2"`, match: true},
		{name: "index 1 is not the second field", ctx: parsed, test: `header :index 1 "x(a" "2"`},
		{name: "date uses the first field", ctx: parsed, test: `date :is "x(d" "year" "1997"`, match: true},
		{name: "date skips the second field", ctx: parsed, test: `date :is "x(d" "year" "1998"`},
		{name: "date index 2 is the second field", ctx: parsed, test: `date :index 2 "x(d" "year" "1998"`, match: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := `require ["date", "index", "relational", "fileinto"];
if ` + tc.test + ` { fileinto "matched"; }
`
			executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
			if err != nil {
				t.Fatalf("compile: %v\n%s", err, script)
			}
			result, err := executor.Evaluate(context.Background(), tc.ctx)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			var want []string
			if tc.match {
				want = []string{"matched"}
			}
			if !slices.Equal(result.Mailboxes, want) {
				t.Errorf("%s: mailboxes = %q, want %q", tc.test, result.Mailboxes, want)
			}
		})
	}
}
