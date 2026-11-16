package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestUnparseablePartHeader is issue #1777: a MIME part whose header does not
// parse (a line without a colon, or folding white space before the first field)
// was skipped by the body test (RFC 5173) while foreverypart and extracttext
// (RFC 5703) read it as a text/plain leaf with no header fields, so extracttext
// found text that body :text and body :content "text" never searched. RFC 5173
// §5.2: "All MIME parts with matching types are searched for the key strings";
// RFC 5703 §3: foreverypart "walks though every MIME part of a message".
func TestUnparseablePartHeader(t *testing.T) {
	const script = `require ["body", "mime", "fileinto", "extracttext", "variables", "foreverypart"];
if body :text :contains "needle" { fileinto "body"; }
if body :content "text" :contains "needle" { fileinto "content"; }
foreverypart { extracttext "x"; if string :contains "${x}" "needle" { fileinto "extract"; } }`
	message := func(partHeader string) string {
		return "From: a@example.com\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: multipart/mixed; boundary=B\r\n" +
			"\r\n" +
			"--B\r\n" +
			partHeader +
			"Content-Type: text/plain\r\n" +
			"\r\n" +
			"needle words\r\n" +
			"--B--\r\n"
	}
	want := []string{"body", "content", "extract"}

	for _, tc := range []struct{ name, partHeader string }{
		{"header that parses", ""},
		{"line without a colon", "Garbage line\r\n"},
		{"folding white space before the first field", " folded\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executor, err := NewSieveExecutorWithExtensions(script, DefaultSieveExtensions)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			result, err := executor.Evaluate(context.Background(), rawContext(t, message(tc.partHeader)))
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if !slices.Equal(result.Mailboxes, want) {
				t.Errorf("mailboxes = %q, want %q", result.Mailboxes, want)
			}
		})
	}
}
