package sieveengine

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// TestValidateScriptIndexOnHeaderAndAddress is issue #1345: the "index"
// extension is in the default [sieve] enabled_extensions and advertised in the
// ManageSieve SIEVE capability, but the header and address tests refused its
// :index and :last ("LoadSpec: unknown tagged argument: index"), so ManageSieve
// PUTSCRIPT, the User API and sora-admin refused valid scripts.
//
// RFC 5260 §6: "The "index" extension, if specified, adds optional :index and
// :last arguments to the header, address, and date tests [...] Specifying
// :last without :index is an error."
func TestValidateScriptIndexOnHeaderAndAddress(t *testing.T) {
	accepted := []string{
		`require "index"; if header :index 2 "Received" "x" { stop; }`,
		`require "index"; if header :index 1 :last "Received" "x" { stop; }`,
		`require "index"; if address :index 1 "From" "a@example.com" { stop; }`,
		`require ["date", "index"]; if date :index 2 "Received" "year" "2026" { stop; }`,
	}
	for _, script := range accepted {
		if err := ValidateScript(script, nil); err != nil {
			t.Errorf("ValidateScript(%s): %v", script, err)
		}
	}

	refused := []struct {
		name    string
		script  string
		wantErr string
	}{
		{":last without :index", `require "index"; if header :last "Received" "x" { stop; }`, ":last requires :index"},
		// Fields are counted "beginning at 1, the first named header field".
		{":index 0", `require "index"; if address :index 0 "From" "a@example.com" { stop; }`, ":index must be 1 or more"},
		{"without require", `if header :index 1 "Received" "x" { stop; }`, "missing require 'index'"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateScript(tc.script, nil)
			if err == nil {
				t.Fatal("ValidateScript accepted the script")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateScript: %v, want an error naming %q", err, tc.wantErr)
			}
		})
	}
}

// TestIndexSelectsOneHeaderField checks that :index limits the header and
// address tests to the one field it names (RFC 5260 §6): "the attempts to
// match a value are limited to the header field fieldno [...] If :last is
// also specified, the count is backwards [...] all the named header fields
// are counted in the order specified by the header-list."
func TestIndexSelectsOneHeaderField(t *testing.T) {
	const script = `require ["index", "fileinto"];
if header :matches :index 2 "Received" "from second.example.net *" { fileinto "second"; }
if header :matches :index 1 :last "Received" "from first.example.net *" { fileinto "last"; }
if header :matches :index 1 "Received" "from first.example.net *" { fileinto "wrong-first"; }
if address :index 2 ["To", "Cc"] "cc@example.org" { fileinto "cc"; }
if address :index 1 ["To", "Cc"] "cc@example.org" { fileinto "wrong-to"; }
`
	executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	result, err := executor.Evaluate(context.Background(), Context{
		EnvelopeFrom: "sender@example.net",
		EnvelopeTo:   "user@example.com",
		Header: map[string][]string{
			"Received": {
				"from third.example.net by mx.example.com; Sun, 15 Nov 2026 10:00:03 +0000",
				"from second.example.net by third.example.net; Sun, 15 Nov 2026 10:00:02 +0000",
				"from first.example.net by second.example.net; Sun, 15 Nov 2026 10:00:01 +0000",
			},
			"From": {"sender@example.net"},
			"To":   {"user@example.com"},
			"Cc":   {"cc@example.org"},
		},
		Message: bodyOnly("body"),
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if want := []string{"second", "last", "cc"}; !slices.Equal(result.Mailboxes, want) {
		t.Errorf("mailboxes = %q, want %q", result.Mailboxes, want)
	}
}
