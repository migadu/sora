package sieveengine

import (
	"context"
	"slices"
	"testing"
)

// TestLeafDecodedByLenientContentType is issue #1776: a text part is decoded by
// the parameters the mime extension reads. "header :mime :param" (RFC 5703)
// parses Content-Type leniently, retrying without trailing semicolons and white
// space; the body test (RFC 5173) and extracttext decoded the part with
// go-message, which parses the raw value with mime.ParseMediaType alone. That
// accepts one trailing ";" but rejects "charset=iso-8859-1;;" and
// "charset=iso-8859-1; ;", so :param saw the charset while the part was matched
// and extracted still in ISO-8859-1.
func TestLeafDecodedByLenientContentType(t *testing.T) {
	const script = `require ["body", "mime", "fileinto", "extracttext", "variables", "foreverypart"];
if body :text :contains "café" { fileinto "body"; }
if header :mime :anychild :param "charset" "Content-Type" "iso-8859-1" { fileinto "param"; }
foreverypart { extracttext "x"; if string :contains "${x}" "café" { fileinto "extract"; } }`
	const latin1 = "caf\xe9 words\r\n" // "café words" in ISO-8859-1
	message := func(contentType, body string) string {
		return "From: a@example.com\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: " + contentType + "\r\n" +
			"\r\n" +
			body
	}
	part := func(contentType string) string {
		return "--B\r\nContent-Type: " + contentType + "\r\n\r\n" + latin1 + "--B--\r\n"
	}
	want := []string{"body", "param", "extract"}

	for _, tc := range []struct{ name, raw string }{
		{"message: one trailing semicolon", message("text/plain; charset=iso-8859-1;", latin1)},
		{"message: two trailing semicolons", message("text/plain; charset=iso-8859-1;;", latin1)},
		{"message: semicolon, space, semicolon", message("text/plain; charset=iso-8859-1; ;", latin1)},
		{"part: two trailing semicolons", message("multipart/mixed; boundary=B", part("text/plain; charset=iso-8859-1;;"))},
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
			if !slices.Equal(result.Mailboxes, want) {
				t.Errorf("mailboxes = %q, want %q", result.Mailboxes, want)
			}
		})
	}
}

// TestLeafUnknownCharsetKeepsTransferDecodeFailure: decoding a part by its
// recovered charset must not let an unknown charset hide an unknown transfer
// encoding. go-message reports only the charset error when both are unknown,
// and the body test tolerates that error to match raw octets, so a part it
// cannot transfer-decode was matched and counted. Before the ";;" form was
// decoded with its charset, go-message saw no charset there and the part was
// skipped; it must stay skipped, like the canonical form.
func TestLeafUnknownCharsetKeepsTransferDecodeFailure(t *testing.T) {
	const script = `require ["body", "fileinto", "relational"];
if body :text :contains "needle" { fileinto "text"; }
if body :text :count "eq" "0" { fileinto "zero"; }
if body :raw :contains "needle" { fileinto "raw"; }`
	want := []string{"zero", "raw"}

	for _, contentType := range []string{
		"text/plain; charset=x-unknown",
		"text/plain; charset=x-unknown;;",
		"text/plain; charset=x-unknown; ;",
	} {
		leaf := "Content-Type: " + contentType + "\r\n" +
			"Content-Transfer-Encoding: x-unknown\r\n" +
			"\r\n" +
			"needle\r\n"
		for _, tc := range []struct{ name, part string }{
			{"part", leaf},
			{"nested message", "Content-Type: message/rfc822\r\n\r\n" + leaf},
		} {
			t.Run(tc.name+"/"+contentType, func(t *testing.T) {
				raw := "From: a@example.com\r\n" +
					"MIME-Version: 1.0\r\n" +
					"Content-Type: multipart/mixed; boundary=B\r\n" +
					"\r\n" +
					"--B\r\n" + tc.part + "--B--\r\n"
				executor, err := NewSieveExecutorWithExtensions(script, DefaultSieveExtensions)
				if err != nil {
					t.Fatalf("compile: %v", err)
				}
				result, err := executor.Evaluate(context.Background(), rawContext(t, raw))
				if err != nil {
					t.Fatalf("evaluate: %v", err)
				}
				if !slices.Equal(result.Mailboxes, want) {
					t.Errorf("mailboxes = %q, want %q", result.Mailboxes, want)
				}
			})
		}
	}
}
