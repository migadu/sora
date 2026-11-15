package sieveengine

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/emersion/go-message"
)

// TestDeleteHeaderNameASCIICase is issue #1593: deleteheader names its field
// under i;ascii-casemap, but ApplyHeaderEdits found the fields to delete with
// go-message's Header.Values/Header.Del. go-message canonicalizes a name only
// when every byte is a token character, so a field named with "(" (valid
// ftext, RFC 5322 §3.6.8) was looked up with the script's spelling and missed
// in the stored message while the script saw it deleted.
//
// RFC 5293 §5: "The field-name is mandatory and always matched as a
// case-insensitive US-ASCII string."
func TestDeleteHeaderNameASCIICase(t *testing.T) {
	// editheader is not in the default [sieve] enabled_extensions.
	extensions := EffectiveExtensions(append(slices.Clone(DefaultSieveExtensions), "editheader"))
	for _, tc := range []struct {
		name    string
		headers string // fields above From/Subject
		action  string
		field   string   // the field checked afterwards, in another ASCII case
		want    []string // its values left in the stored message, top to bottom
	}{
		{name: "all", headers: "X(a: 1\r\n", action: `deleteheader "x(A";`, field: "X(a"},
		{name: "all, two spellings", headers: "X(a: 1\r\nx(A: 2\r\n", action: `deleteheader "X(A";`, field: "x(a"},
		{name: "index", headers: "X(a: 1\r\nX(a: 2\r\n", action: `deleteheader :index 1 "x(A";`,
			field: "X(a", want: []string{"2"}},
		{name: "last index", headers: "X(a: 1\r\nX(a: 2\r\n", action: `deleteheader :index 1 :last "x(A";`,
			field: "X(a", want: []string{"1"}},
		{name: "index counts both spellings", headers: "X(a: 1\r\nx(A: 2\r\nX(a: 3\r\n",
			action: `deleteheader :index 2 "X(A";`, field: "x(a", want: []string{"1", "3"}},
		{name: "value", headers: "X(a: 1\r\nX(a: 2\r\n", action: `deleteheader :is "x(A" "2";`,
			field: "X(a", want: []string{"1"}},
		{name: "other name kept", headers: "X(a: 1\r\nX[a: 2\r\n", action: `deleteheader "x(A";`,
			field: "x[A", want: []string{"2"}},
		// Control: a token name is canonicalized by go-message on both sides.
		{name: "token name", headers: "X-Foo: 1\r\n", action: `deleteheader "x-FOO";`, field: "X-Foo"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script := `require ["fileinto", "editheader"];
` + tc.action + `
if exists "` + tc.field + `" { fileinto "still"; }
`
			executor, err := NewSieveExecutorWithExtensions(script, extensions)
			if err != nil {
				t.Fatalf("compile: %v\n%s", err, script)
			}
			raw := tc.headers +
				"From: a@example.com\r\n" +
				"Subject: s\r\n" +
				"\r\n" +
				"body\r\n"
			result, err := executor.Evaluate(context.Background(), rawContext(t, raw))
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			// What the script saw after its own edit.
			wantMailboxes := []string(nil)
			if len(tc.want) > 0 {
				wantMailboxes = []string{"still"}
			}
			if !slices.Equal(result.Mailboxes, wantMailboxes) {
				t.Errorf("mailboxes = %q, want %q", result.Mailboxes, wantMailboxes)
			}

			edited, err := ApplyHeaderEdits([]byte(raw), result.HeaderEdits)
			if err != nil {
				t.Fatalf("ApplyHeaderEdits: %v", err)
			}
			entity, err := message.Read(strings.NewReader(string(edited)))
			if err != nil {
				t.Fatalf("read edited message: %v", err)
			}
			var got []string
			for fields := entity.Header.Fields(); fields.Next(); {
				if lowerASCII(fields.Key()) == lowerASCII(tc.field) {
					got = append(got, fields.Value())
				}
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("stored %s values = %q, want %q\n%s", tc.field, got, tc.want, edited)
			}
			for _, f := range []string{"From", "Subject"} {
				if entity.Header.Get(f) == "" {
					t.Errorf("%s field lost\n%s", f, edited)
				}
			}
		})
	}
}
