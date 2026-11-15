package sieveengine

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/emersion/go-message"
)

// TestDeleteHeaderCount is issue #1529: with editheader enabled,
// `deleteheader :count ... <value-patterns>` panicked when the action ran
// (go-sieve matched each field value with its string matcher, which panics on
// :count), so the script's actions were dropped and the message was kept in
// INBOX. RFC 5293 §5 matches the value-patterns "as if by the "header" test",
// and RFC 5231 §4.2: "The Header Test counts the total number of instances of
// the specified fields."
func TestDeleteHeaderCount(t *testing.T) {
	const script = `require ["editheader", "relational", "comparator-i;ascii-numeric", "fileinto"];
deleteheader :count "eq" :comparator "i;ascii-numeric" "x-foo" "1";
fileinto "one";
`
	// editheader is not in the default [sieve] enabled_extensions.
	extensions := EffectiveExtensions(append(slices.Clone(DefaultSieveExtensions), "editheader"))
	if !slices.Contains(extensions, "editheader") {
		t.Fatalf("editheader not enabled: %q", extensions)
	}
	// What ManageSieve PUTSCRIPT checks.
	if err := ValidateScript(script, extensions); err != nil {
		t.Fatalf("ValidateScript: %v", err)
	}
	executor, err := NewSieveExecutorWithExtensions(script, extensions)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, tc := range []struct {
		name    string
		headers string
		want    []string // X-Foo values left after the header edits
	}{
		{name: "count holds", headers: "X-Foo: first\r\n", want: nil},
		{name: "count does not hold", headers: "X-Foo: first\r\nX-Foo: second\r\n", want: []string{"first", "second"}},
		{name: "no field", want: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.headers +
				"From: sender@example.net\r\n" +
				"To: user@example.com\r\n" +
				"\r\n" +
				"body\r\n"
			result, err := executor.Evaluate(context.Background(), rawContext(t, raw))
			if err != nil {
				t.Fatalf("evaluate: %.200v", err)
			}
			if !slices.Equal(result.Mailboxes, []string{"one"}) {
				t.Errorf("mailboxes = %q, want [\"one\"]", result.Mailboxes)
			}
			edited, err := ApplyHeaderEdits([]byte(raw), result.HeaderEdits)
			if err != nil {
				t.Fatalf("ApplyHeaderEdits: %v", err)
			}
			entity, err := message.Read(strings.NewReader(string(edited)))
			if err != nil {
				t.Fatalf("read edited message: %v", err)
			}
			if got := entity.Header.Values("X-Foo"); !slices.Equal(got, tc.want) {
				t.Errorf("X-Foo = %q, want %q", got, tc.want)
			}
		})
	}
}
