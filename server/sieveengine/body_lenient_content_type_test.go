package sieveengine

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// TestBodyLenientContentType is issue #1726: the body test (RFC 5173) and the
// mime extension (RFC 5703) parsed a Content-Type with different parsers. Go's
// mime.ParseMediaType accepts one trailing ";" but rejects "boundary=B;;" and
// "boundary=B; ;"; the mime extension retries without the trailing semicolons
// and sees the parts, while the body test kept no parameters, found no
// boundary and never reached the text/plain part that extracttext and
// "header :mime :anychild" see.
func TestBodyLenientContentType(t *testing.T) {
	const agree = `require ["body", "mime", "fileinto", "extracttext", "variables", "foreverypart"];
if body :text :contains "needle" { fileinto "body"; }
if header :mime :anychild :contenttype "Content-Type" "text/plain" { fileinto "mime"; }
foreverypart { extracttext "x"; if string :contains "${x}" "needle" { fileinto "extract"; } }`
	text := "--C\r\nContent-Type: text/plain\r\n\r\nneedle words\r\n--C--\r\n"
	message := func(contentType, body string) string {
		return "From: a@example.com\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: " + contentType + "\r\n" +
			"\r\n" +
			body
	}
	all := []string{"body", "mime", "extract"}

	for _, tc := range []struct {
		name, raw, script string
		want              []string
	}{
		{"message: one trailing semicolon", message("multipart/mixed; boundary=C;", text), agree, all},
		{"message: two trailing semicolons", message("multipart/mixed; boundary=C;;", text), agree, all},
		{"message: semicolon, space, semicolon", message("multipart/mixed; boundary=C; ;", text), agree, all},
		{"part: two trailing semicolons", message("multipart/mixed; boundary=B",
			"--B\r\nContent-Type: multipart/alternative; boundary=C;;\r\n\r\n"+text+"--B--\r\n"), agree, all},
		// RFC 5173 §5.2: a matching multipart has only its prologue and
		// epilogue searched, not its parts.
		{":content multipart", message("multipart/mixed; boundary=C;;", text),
			`require ["body", "fileinto"];
if body :content "multipart" :contains "needle" { fileinto "body"; }`, nil},
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
