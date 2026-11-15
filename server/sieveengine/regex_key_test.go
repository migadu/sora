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
		// Issue #1428: 1000 bytes that compile to about a million instructions.
		{"program too large", `require "regex"; if header :regex "Received" "(?:` + strings.Repeat("a", 990) + `){1000}" { stop; }`},
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
// makes a key of a few bytes such as "(?:abcdefghi){1000}" compile to a program
// of 9000 instructions, within the bound (#1428), which allocates some 1.7 MB
// and keeps some 0.4 MB, so compiling and keeping every key of a script would
// make one PUTSCRIPT under ManageSieve's 16 KB limit (the User API takes 64 KB)
// allocate over a gigabyte, and the delivery script cache hold some 300 MB for
// each such script.
func TestValidateScriptDoesNotCompileRegexKeys(t *testing.T) {
	key := `"(?:abcdefghi){1000}"`
	keys := make([]string, 40)
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

// evaluateReceived runs script against a message with the given number of
// Received fields and returns what Evaluate allocated.
func evaluateReceived(t *testing.T, script string, fields int) (uint64, error) {
	t.Helper()
	executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	received := make([]string, fields)
	for i := range received {
		received[i] = "from host.example.com by mx.example.org"
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err = executor.Evaluate(context.Background(), Context{
		EnvelopeFrom: "sender@example.com",
		EnvelopeTo:   "user@example.com",
		Header:       map[string][]string{"Received": received, "Subject": {"x"}, "From": {"sender@example.com"}},
		Message:      bodyOnly("body"),
	})
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc, err
}

// TestRegexKeyTooLargeRefusedAtDelivery is issue #1428: a :regex key known only
// at delivery, through a variable, whose program would be too large is refused
// then, as the same key written as a string is refused by ValidateScript. It was
// compiled, to about a million instructions (some 45 MB), for each of the ten
// Received fields: some 300 ms and 2 GB for every message to the account.
func TestRegexKeyTooLargeRefusedAtDelivery(t *testing.T) {
	script := `require ["variables", "regex", "fileinto"];
set "p" "(?:` + strings.Repeat("a", 990) + `){1000}";
if header :regex "Received" "${p}" { fileinto "hit"; }
`
	if _, err := evaluateReceived(t, script, 10); err == nil || !strings.Contains(err.Error(), "too complex") {
		t.Fatalf("Evaluate: %v, want a too complex error", err)
	}
}

// TestRegexKeyCompiledOncePerDelivery is issue #1428: a :regex key is compiled
// once per delivery, not once for every value its test matches it against, as
// Pigeonhole compiles each key once per match operation. The key compiles to
// 8000 instructions, within the bound.
func TestRegexKeyCompiledOncePerDelivery(t *testing.T) {
	const key = "(?:abcdefgh){1000}"
	scripts := map[string]string{
		"constant": `require ["regex", "fileinto"];
if header :regex "Received" "` + key + `" { fileinto "hit"; }
`,
		"variable": `require ["variables", "regex", "fileinto"];
set "p" "` + key + `";
if header :regex "Received" "${p}" { fileinto "hit"; }
`,
	}
	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			one, err := evaluateReceived(t, script, 1)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			ten, err := evaluateReceived(t, script, 10)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if ten > 2*one {
				t.Fatalf("matching the key against ten Received fields allocated %d KB, against one %d KB", ten>>10, one>>10)
			}
		})
	}
}
