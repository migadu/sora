package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestDateCountFirstField is issue #1431: the date test's :count counted every
// field of the header holding a valid date, so two valid Resent-Date: fields
// counted 2. RFC 5260 §4: "If multiple header fields with the same name are
// present, only the first field that is found is used." and "The count of a
// date test is 1 if the specified field exists and contains a valid date; 0,
// otherwise."
func TestDateCountFirstField(t *testing.T) {
	const script = `require ["date", "relational", "comparator-i;ascii-numeric", "fileinto"];
if date :count "eq" :comparator "i;ascii-numeric" "resent-date" "year" "1" { fileinto "one"; }
elsif date :count "eq" :comparator "i;ascii-numeric" "resent-date" "year" "0" { fileinto "zero"; }
`
	// What ManageSieve PUTSCRIPT checks, with the default [sieve] enabled_extensions.
	if err := ValidateScript(script, nil); err != nil {
		t.Fatalf("ValidateScript: %v", err)
	}
	executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, tc := range []struct {
		name    string
		headers string
		want    []string
	}{
		{
			name: "two valid fields",
			headers: "Resent-Date: Wed, 12 Nov 2014 18:18:31 +0100\r\n" +
				"Resent-Date: Wed, 12 Nov 2014 18:18:30 +0100\r\n",
			want: []string{"one"},
		},
		{
			name: "invalid first field",
			headers: "Resent-Date: not a date\r\n" +
				"Resent-Date: Wed, 12 Nov 2014 18:18:30 +0100\r\n",
			want: []string{"zero"},
		},
		{
			name: "valid first field",
			headers: "Resent-Date: Wed, 12 Nov 2014 18:18:31 +0100\r\n" +
				"Resent-Date: not a date\r\n",
			want: []string{"one"},
		},
		{
			name: "no field",
			want: []string{"zero"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The header map comes from a parse of the raw message, as LMTP and
			// the Admin API delivery build it, so the field order is kept.
			result, err := executor.Evaluate(context.Background(), rawContext(t,
				tc.headers+
					"From: sender@example.net\r\n"+
					"To: user@example.com\r\n"+
					"\r\n"+
					"body\r\n"))
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if !slices.Equal(result.Mailboxes, tc.want) {
				t.Errorf("mailboxes = %q, want %q", result.Mailboxes, tc.want)
			}
		})
	}
}

// TestCurrentDateCount: RFC 5260 §5: "The :count value of a currentdate test is
// always 1." go-sieve handed currentdate's :count to its string matcher, which
// panics on :count, so the script failed and its fileinto was dropped.
func TestCurrentDateCount(t *testing.T) {
	const script = `require ["date", "relational", "comparator-i;ascii-numeric", "fileinto"];
if currentdate :count "eq" :comparator "i;ascii-numeric" "year" "1" { fileinto "one"; }
`
	if err := ValidateScript(script, nil); err != nil {
		t.Fatalf("ValidateScript: %v", err)
	}
	executor, err := NewSieveExecutorWithExtensions(script, EffectiveExtensions(nil))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	result, err := executor.Evaluate(context.Background(), rawContext(t,
		"From: sender@example.net\r\n"+
			"To: user@example.com\r\n"+
			"\r\n"+
			"body\r\n"))
	if err != nil {
		t.Fatalf("evaluate: %.200v", err)
	}
	if !slices.Equal(result.Mailboxes, []string{"one"}) {
		t.Errorf("mailboxes = %q, want [\"one\"]", result.Mailboxes)
	}
}
