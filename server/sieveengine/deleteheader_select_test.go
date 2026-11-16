package sieveengine

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// TestDeleteHeaderEmptyValueMatch is issue #1623: a deletion was handed over with
// the value of the field it selected, and an empty value read as "no
// value-patterns", so a value-pattern that matched an empty field deleted every
// field of the name, in the script's view and in the stored message. RFC 5293 §5:
// "The value-patterns, if specified, restrict which occurrences of the header
// field are deleted to those whose values match any of the specified
// value-patterns".
func TestDeleteHeaderEmptyValueMatch(t *testing.T) {
	const script = `require ["fileinto", "editheader"];
deleteheader :is "X-Foo" "";
if header :is "X-Foo" "keep" { fileinto "kept"; }
`
	// editheader is not in the default [sieve] enabled_extensions.
	extensions := EffectiveExtensions(append(slices.Clone(DefaultSieveExtensions), "editheader"))
	executor, err := NewSieveExecutorWithExtensions(script, extensions)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	const raw = "X-Foo:\r\n" +
		"X-Foo: keep\r\n" +
		"From: a@example.com\r\n" +
		"Subject: s\r\n" +
		"X-Foo: \r\n" +
		"\r\nbody\r\n"
	result, err := executor.Evaluate(context.Background(), rawContext(t, raw))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !slices.Equal(result.Mailboxes, []string{"kept"}) {
		t.Errorf("mailboxes = %q, want [\"kept\"]: the script no longer sees X-Foo: keep", result.Mailboxes)
	}
	got, err := ApplyHeaderEdits([]byte(raw), result.HeaderEdits)
	if err != nil {
		t.Fatalf("ApplyHeaderEdits: %v", err)
	}
	want := "X-Foo: keep\r\n" +
		"From: a@example.com\r\n" +
		"Subject: s\r\n" +
		"\r\nbody\r\n"
	if string(got) != want {
		t.Errorf("edited message:\n%q\nwant:\n%q", got, want)
	}
}

// TestDeleteHeaderIndexZero is the rest of issue #1623: `deleteheader :index 0`
// read as no :index at all and deleted every field of the name. RFC 5293 §5
// counts the fields "beginning at 1, the first named header field", so there is
// no field 0; go-sieve refuses the script, as it refuses :index 0 on the header,
// address and date tests of the index extension, and so does a PUTSCRIPT.
func TestDeleteHeaderIndexZero(t *testing.T) {
	extensions := EffectiveExtensions(append(slices.Clone(DefaultSieveExtensions), "editheader"))
	for _, script := range []string{
		`require "editheader"; deleteheader :index 0 "X-Foo";`,
		`require "editheader"; deleteheader :index 0 :last "X-Foo";`,
		`require "editheader"; deleteheader :index 0 :is "X-Foo" "keep";`,
	} {
		err := ValidateScript(script, extensions)
		if err == nil || !strings.Contains(err.Error(), ":index must be 1 or more") {
			t.Errorf("%s: ValidateScript = %v, want an error that :index must be 1 or more", script, err)
		}
	}
	if err := ValidateScript(`require "editheader"; deleteheader :index 1 :last "X-Foo";`, extensions); err != nil {
		t.Errorf(":index 1: %v", err)
	}
}
