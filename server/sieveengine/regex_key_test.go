package sieveengine

import (
	"context"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestValidateScriptRefusesMalformedRegexKey is issue #1332: a :regex key that is
// not a regular expression loaded, so ManageSieve PUTSCRIPT, the User API and
// sora-admin stored the script, and its test then failed at every delivery with
// "regex compile error". draft-murchison-sieve-regex-08 §3: "Implementations
// SHOULD reject regular expressions that are unsupported by this specification as
// a syntax error." Pigeonhole refuses such a key when it validates the script.
func TestValidateScriptRefusesMalformedRegexKey(t *testing.T) {
	refused := []struct {
		name   string
		script string
	}{
		{"header (issue)", `require "regex"; if header :regex "Subject" "(" { stop; }`},
		{"one bad key of several", `require "regex"; if header :regex "Subject" ["^a", "[z-a]"] { stop; }`},
		{"address", `require "regex"; if address :regex "from" "a{2,1}" { stop; }`},
		{"string", `require ["variables", "regex"]; if string :regex "abc" "(" { stop; }`},
		{"body", `require ["body", "regex"]; if body :regex "(" { stop; }`},
		{"hasflag", `require ["imap4flags", "regex"]; if hasflag :regex "(" { stop; }`},
		{"pattern too long", `require "regex"; if header :regex "Subject" "` + strings.Repeat("a", 1001) + `" { stop; }`},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateScript(tc.script, nil)
			if err == nil {
				t.Fatal("ValidateScript accepted the script")
			}
			if !strings.Contains(err.Error(), "malformed pattern") {
				t.Fatalf("ValidateScript: %v, want a malformed pattern error", err)
			}
		})
	}

	accepted := []string{
		`require "regex"; if header :regex "Subject" ["^a", "b(c)d$"] { stop; }`,
		// A key with a variable is known only when the test runs.
		`require ["variables", "regex"]; set "p" "("; if header :regex "Subject" "${p}" { stop; }`,
	}
	for _, script := range accepted {
		if err := ValidateScript(script, nil); err != nil {
			t.Errorf("ValidateScript(%s): %v", script, err)
		}
	}
}

// ValidateScript checks a :regex key without compiling it. Counted repetition
// makes a 1000-byte key such as "(?:a...a){1000}" compile to a program of some
// 45 MB, so compiling and keeping every key of a script made one 15 KB
// PUTSCRIPT (under ManageSieve's 16 KB limit; the User API takes 64 KB)
// allocate over 3 GB, and the delivery script cache hold some 700 MB for each
// such script.
func TestValidateScriptDoesNotCompileRegexKeys(t *testing.T) {
	key := `"(?:` + strings.Repeat("a", 990) + `){1000}"`
	keys := make([]string, 15)
	for i := range keys {
		keys[i] = key
	}
	script := `require "regex"; if header :regex "Subject" [` + strings.Join(keys, ", ") + `] { stop; }`

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err := ValidateScript(script, nil)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("ValidateScript: %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16<<20 {
		t.Fatalf("ValidateScript of a %d-byte script allocated %d MB, want under 16 MB", len(script), allocated>>20)
	}
}

// A :regex key checked when the script loads still files the message and sets
// the match variables at delivery.
func TestRegexKeyMatchesAtDelivery(t *testing.T) {
	script := `require ["regex", "variables", "fileinto"];
if header :regex "Subject" "^invoice ([0-9]+)$" { fileinto "Invoices/${1}"; }
`
	if err := ValidateScript(script, nil); err != nil {
		t.Fatalf("ValidateScript: %v", err)
	}
	executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	result, err := executor.Evaluate(context.Background(), Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "user@example.com",
		Header:       map[string][]string{"Subject": {"invoice 42"}, "From": {"sender@example.com"}},
		Message:      bodyOnly("body"),
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if want := []string{"Invoices/42"}; !slices.Equal(result.Mailboxes, want) {
		t.Fatalf("Mailboxes = %q, want %q", result.Mailboxes, want)
	}
}
