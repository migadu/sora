package sieveengine

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// TestPartHeaderNonTokenFieldName is issue #1638: a MIME part whose header has
// a field name holding a byte outside the RFC 7230 token set, such as "(", lost
// its whole header, so the body test skipped the part and the :mime tests saw it
// with no fields. RFC 5322 §3.6.8: "field-name = 1*ftext", "ftext = %d33-57 /
// %d59-126", and MIME part headers use the same field syntax (RFC 2045 §3).
// Header names compare under i;ascii-casemap (RFC 5228 §2.7), so "X(a" and
// "x(A" name one field in a part as they do in the message header.
func TestPartHeaderNonTokenFieldName(t *testing.T) {
	message := func(partFields string) string {
		return "From: a@example.com\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: multipart/mixed; boundary=B\r\n" +
			"\r\n" +
			"--B\r\n" +
			"Content-Type: text/plain\r\n" +
			partFields +
			"\r\n" +
			"secret words\r\n" +
			"--B--\r\n"
	}

	for _, tc := range []struct {
		name, partFields, script string
		want                     []string
	}{
		{name: "body and mime without the field", script: `require ["body", "mime", "fileinto"];
if body :text :contains "secret" { fileinto "body"; }
if header :mime :anychild :contains "content-type" "text/plain" { fileinto "mime"; }`,
			want: []string{"body", "mime"}},
		{name: "body and mime with ( in a field name", partFields: "X(a: 1\r\n", script: `require ["body", "mime", "fileinto"];
if body :text :contains "secret" { fileinto "body"; }
if header :mime :anychild :contains "content-type" "text/plain" { fileinto "mime"; }`,
			want: []string{"body", "mime"}},
		{name: "names i;ascii-casemap folds to one", partFields: "X(a: 1\r\nx(A: 2\r\n", script: `require ["mime", "fileinto"];
if header :mime :anychild :is "x(a" "1" { fileinto "one"; }
if header :mime :anychild :is "X(A" "2" { fileinto "two"; }`,
			want: []string{"one", "two"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executor, err := NewSieveExecutorWithExtensions(tc.script, DefaultSieveExtensions)
			if err != nil {
				t.Fatalf("compile: %v\n%s", err, tc.script)
			}
			result, err := executor.Evaluate(context.Background(), rawContext(t, message(tc.partFields)))
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if !slices.Equal(result.Mailboxes, tc.want) {
				t.Errorf("%s\nmailboxes = %q, want %q", strings.TrimSpace(tc.script), result.Mailboxes, tc.want)
			}
		})
	}
}
