package sieveengine

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// TestBodyFirstContentType is issue #1685: a message or part with its
// Content-Type field more than once had two content types in one evaluation.
// The body test (RFC 5173) read the last field, while the :mime tests,
// foreverypart and extracttext (RFC 5703) read the first, so a part that is
// text/plain to extracttext was application/octet-stream to "body :text" and its
// text never reached a body rule. Both read the first now, as go-message's
// parser does for the message delivery hands to Sieve.
func TestBodyFirstContentType(t *testing.T) {
	const (
		agree = `require ["body", "mime", "fileinto", "extracttext", "variables", "foreverypart"];
if body :text :contains "needle" { fileinto "body"; }
if header :mime :anychild :contenttype "Content-Type" "text/plain" { fileinto "mime"; }
foreverypart { extracttext "x"; if string :contains "${x}" "needle" { fileinto "extract"; } }`
		bodyText = `require ["body", "fileinto"];
if body :text :contains "needle" { fileinto "body"; }`
	)
	multipart := func(partFields, partBody string) string {
		return "From: a@example.com\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: multipart/mixed; boundary=B\r\n" +
			"\r\n" +
			"--B\r\n" +
			partFields +
			"\r\n" +
			partBody + "\r\n" +
			"--B--\r\n"
	}
	single := func(fields string) string {
		return "From: a@example.com\r\n" +
			"MIME-Version: 1.0\r\n" +
			fields +
			"\r\n" +
			"needle words\r\n"
	}

	for _, tc := range []struct {
		name, raw, script string
		want              []string
	}{
		{"part: text/plain first", multipart("Content-Type: text/plain\r\nContent-Type: application/octet-stream\r\n", "needle words"),
			agree, []string{"body", "mime", "extract"}},
		{"part: application/octet-stream first", multipart("Content-Type: application/octet-stream\r\nContent-Type: text/plain\r\n", "needle words"),
			bodyText, nil},
		{"part: base64 first", multipart("Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\nContent-Transfer-Encoding: 7bit\r\n", "bmVlZGxlIHdvcmRz"),
			bodyText, []string{"body"}},
		{"message: text/plain first", single("Content-Type: text/plain\r\nContent-Type: application/octet-stream\r\n"),
			bodyText, []string{"body"}},
		{"message: application/octet-stream first", single("Content-Type: application/octet-stream\r\nContent-Type: text/plain\r\n"),
			bodyText, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executor, err := NewSieveExecutorWithExtensions(tc.script, DefaultSieveExtensions)
			if err != nil {
				t.Fatalf("compile: %v\n%s", err, tc.script)
			}
			result, err := executor.Evaluate(context.Background(), rawContext(t, tc.raw))
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if !slices.Equal(result.Mailboxes, tc.want) {
				t.Errorf("%s\nmailboxes = %q, want %q", strings.TrimSpace(tc.script), result.Mailboxes, tc.want)
			}
		})
	}
}
