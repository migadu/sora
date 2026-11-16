package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestBodyUnknownCharsetUndecodableTransferEncoding: a part whose charset is
// unknown is matched as raw octets, but one whose transfer encoding cannot be
// decoded is left out of :text and :content (and their :count) even when its
// charset is unknown too. RFC 5173 §5.2: "MIME parts that cannot be decoded
// and converted MAY be treated as plain US-ASCII, omitted, or processed
// according to local conventions." :raw does not decode and still sees it.
func TestBodyUnknownCharsetUndecodableTransferEncoding(t *testing.T) {
	const script = `require ["body", "fileinto", "relational", "comparator-i;ascii-numeric"];
if body :text :contains "needle" { fileinto "text"; }
if body :text :count "eq" :comparator "i;ascii-numeric" "0" { fileinto "text-count-0"; }
if body :content "text" :contains "needle" { fileinto "content"; }
if body :raw :contains "needle" { fileinto "raw"; }`
	message := func(contentType, encoding, body string) string {
		return "From: a@example.com\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: " + contentType + "\r\n" +
			"Content-Transfer-Encoding: " + encoding + "\r\n" +
			"\r\n" +
			body
	}
	part := func(encoding string) string {
		return "--B\r\nContent-Type: text/plain; charset=x-unknown\r\nContent-Transfer-Encoding: " +
			encoding + "\r\n\r\nneedle\r\n--B--\r\n"
	}

	for _, tc := range []struct {
		name, raw string
		want      []string
	}{
		{"unknown charset", message("text/plain; charset=x-unknown", "7bit", "needle\r\n"),
			[]string{"text", "content", "raw"}},
		{"unknown charset and transfer encoding", message("text/plain; charset=x-unknown", "x-unknown", "needle\r\n"),
			[]string{"text-count-0", "raw"}},
		{"part: unknown charset and transfer encoding",
			message("multipart/mixed; boundary=B", "7bit", part("x-unknown")),
			[]string{"text-count-0", "raw"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executor, err := NewSieveExecutorWithExtensions(script, DefaultSieveExtensions)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			result, err := executor.Evaluate(context.Background(), rawContext(t, tc.raw))
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if !slices.Equal(result.Mailboxes, tc.want) {
				t.Errorf("mailboxes = %q, want %q", result.Mailboxes, tc.want)
			}
		})
	}
}
