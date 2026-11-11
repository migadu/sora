package helpers

import (
	"fmt"
	"strings"
	"testing"
)

func TestMessagePreviewSkipsMultipartAttachments(t *testing.T) {
	for _, tc := range []struct {
		name, disposition, leafType, body, want string
	}{
		{
			name:        "alternative attachment before plain body",
			disposition: "attachment; filename=notes.mime",
			leafType:    "text/plain",
			body:        "Content-Type: text/plain\r\n\r\nActual message",
			want:        "Actual message",
		},
		{
			name:        "inline leaf cannot override attachment ancestor",
			disposition: "attachment",
			leafType:    "text/plain\r\nContent-Disposition: inline",
			body:        "Content-Type: text/plain\r\n\r\nActual message",
			want:        "Actual message",
		},
		{
			name:        "attached plain text cannot override HTML body",
			disposition: "attachment",
			leafType:    "text/plain",
			body:        "Content-Type: text/html\r\n\r\n<p>Actual message</p>",
			want:        "Actual message",
		},
		{
			name:        "attached HTML cannot become fallback",
			disposition: "attachment",
			leafType:    "text/html",
			body:        "Content-Type: text/plain\r\n\r\n ",
		},
		{
			name:        "attachment with malformed filename parameter",
			disposition: "AtTaChMeNt; filename=private notes.mime",
			leafType:    "text/plain",
			body:        "Content-Type: text/plain\r\n\r\nActual message",
			want:        "Actual message",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := "Content-Type: multipart/mixed; boundary=outer\r\n\r\n" +
				"--outer\r\nContent-Type: multipart/alternative; boundary=attached\r\n" +
				"Content-Disposition: " + tc.disposition + "\r\n\r\n" +
				"--attached\r\nContent-Type: " + tc.leafType + "\r\n\r\nAttached secret\r\n" +
				"--attached--\r\n--outer\r\n" + tc.body + "\r\n--outer--\r\n"
			if got := MessagePreview(strings.NewReader(msg)); got != tc.want {
				t.Errorf("MessagePreview() = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("root attachment", func(t *testing.T) {
		msg := "Content-Type: multipart/alternative; boundary=b\r\n" +
			"Content-Disposition: attachment\r\n\r\n" +
			"--b\r\nContent-Type: text/plain\r\nContent-Disposition: inline\r\n\r\nAttached secret\r\n--b--\r\n"
		if got := MessagePreview(strings.NewReader(msg)); got != "" {
			t.Errorf("MessagePreview() = %q, want no attachment text", got)
		}
	})
}

func TestMessagePreviewMIMETraversal(t *testing.T) {
	t.Run("nested inline alternative", func(t *testing.T) {
		msg := "Content-Type: multipart/mixed; boundary=outer\r\n\r\n" +
			"--outer\r\nContent-Type: multipart/alternative; boundary=inner\r\nContent-Disposition: inline\r\n\r\n" +
			"--inner\r\nContent-Type: text/html\r\n\r\n<p>HTML alternative</p>\r\n" +
			"--inner\r\nContent-Type: text/plain\r\n\r\nPlain alternative\r\n--inner--\r\n--outer--\r\n"
		if got := MessagePreview(strings.NewReader(msg)); got != "Plain alternative" {
			t.Errorf("MessagePreview() = %q, want plain alternative", got)
		}
	})

	t.Run("unknown charset does not discard usable child", func(t *testing.T) {
		msg := "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
			"--b\r\nContent-Type: text/plain; charset=unknown-preview-charset\r\n\r\nASCII body\r\n--b--\r\n"
		if got := MessagePreview(strings.NewReader(msg)); got != "ASCII body" {
			t.Errorf("MessagePreview() = %q, want ASCII body", got)
		}
	})

	t.Run("depth limit still permits shallow sibling", func(t *testing.T) {
		part := "Content-Type: text/plain\r\n\r\nDeep text"
		for depth := 0; depth < 64; depth++ {
			part = fmt.Sprintf("Content-Type: multipart/mixed; boundary=b%d\r\n\r\n--b%d\r\n%s\r\n--b%d--\r\n", depth, depth, part, depth)
		}
		msg := "Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\n" + part +
			"\r\n--outer\r\nContent-Type: text/plain\r\n\r\nShallow text\r\n--outer--\r\n"
		if got := MessagePreview(strings.NewReader(msg)); got != "Shallow text" {
			t.Errorf("MessagePreview() = %q, want shallow sibling after depth limit", got)
		}
	})
}

func previewMIMEMultipart(subtype, boundary string, parts ...string) string {
	return "Content-Type: multipart/" + subtype + "; boundary=" + boundary + "\r\n\r\n--" + boundary + "\r\n" +
		strings.Join(parts, "\r\n--"+boundary+"\r\n") + "\r\n--" + boundary + "--\r\n"
}

func TestMessagePreviewDispositionDefaults(t *testing.T) {
	plain := "Content-Type: text/plain\r\n\r\nActual inline body"
	privateText := "Content-Type: text/plain\r\nContent-Disposition: x-private; filename=private.txt\r\n\r\nPrivate attachment"
	privateMultipart := "Content-Disposition: X-PRIVATE; filename=private.mime\r\n" +
		previewMIMEMultipart("alternative", "private", "Content-Type: text/plain\r\nContent-Disposition: inline\r\n\r\nPrivate attachment")
	for _, tc := range []struct{ name, raw, want string }{
		{"unknown text disposition", previewMIMEMultipart("mixed", "mixed", privateText, plain), "Actual inline body"},
		{"unknown multipart disposition", previewMIMEMultipart("mixed", "mixed", privateMultipart, plain), "Actual inline body"},
		{"unknown root text disposition", privateText, ""},
		{"unknown root multipart disposition", privateMultipart, ""},
		{"unknown disposition with malformed parameters", previewMIMEMultipart("mixed", "mixed",
			"Content-Type: text/plain\r\nContent-Disposition: X-PRIVATE; filename=private note.txt\r\n\r\nPrivate attachment", plain), "Actual inline body"},
		{"malformed disposition without type", previewMIMEMultipart("mixed", "mixed",
			"Content-Type: text/plain\r\nContent-Disposition: ; filename=private.txt\r\n\r\nPrivate attachment", plain), "Actual inline body"},
		{"quoted attachment disposition", previewMIMEMultipart("mixed", "mixed",
			"Content-Type: text/plain\r\nContent-Disposition: \"attachment\"; filename=private.txt\r\n\r\nPrivate attachment", plain), "Actual inline body"},
		{"attachment with unclosed comment", previewMIMEMultipart("mixed", "mixed",
			"Content-Type: text/plain\r\nContent-Disposition: ATTACHMENT (unclosed\r\n\r\nPrivate attachment", plain), "Actual inline body"},
		{"inline disposition with malformed parameters", "Content-Type: text/plain\r\nContent-Disposition: INLINE; filename=inline note.txt\r\n\r\nInline body", "Inline body"},
		{"absent disposition", plain, "Actual inline body"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MessagePreview(strings.NewReader(tc.raw)); got != tc.want {
				t.Errorf("MessagePreview() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMessagePreviewMIMERecovery(t *testing.T) {
	plain := "Content-Type: text/plain\r\n\r\nActual inline body"
	for _, tc := range []struct{ name, raw, want string }{
		{"unknown attachment coding", previewMIMEMultipart("mixed", "mixed",
			"Content-Type: application/octet-stream\r\nContent-Disposition: attachment\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nbegin 600 notes.bin\r\nencoded attachment", plain), "Actual inline body"},
		{"unknown text coding is not shown raw", previewMIMEMultipart("mixed", "mixed",
			"Content-Type: text/plain\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nencoded text is not the body", plain), "Actual inline body"},
		{"root unknown coding is not shown raw", "Content-Type: text/plain\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nencoded text is not the body", ""},
		{"unknown coding and charset are not shown raw", previewMIMEMultipart("mixed", "mixed",
			"Content-Type: text/plain; charset=unknown-preview-charset\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nencoded text is not the body", plain), "Actual inline body"},
		{"root unknown coding and charset are not shown raw", "Content-Type: text/plain; charset=unknown-preview-charset\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nencoded text is not the body", ""},
		{"multipart ignores unsupported transfer coding", "Content-Transfer-Encoding: x-uuencode\r\n" + previewMIMEMultipart("mixed", "mixed", plain), "Actual inline body"},
		{"padded known coding", "Content-Type: text/plain\r\nContent-Transfer-Encoding:  8bit \t\r\n\r\nActual inline body", "Actual inline body"},
		{"malformed inner multipart still permits parent sibling", previewMIMEMultipart("mixed", "mixed",
			"Content-Type: text/html\r\n\r\n<p>HTML fallback</p>",
			"Content-Type: multipart/related\r\n\r\nBroken multipart without a boundary", plain), "Actual inline body"},
		{"malformed inner part headers still permit parent sibling", previewMIMEMultipart("mixed", "mixed",
			"Content-Type: multipart/mixed; boundary=inner\r\n\r\n--inner\r\nnot a header\r\n\r\nBroken part\r\n--inner--\r\n", plain), "Actual inline body"},
		{"usable plain type with malformed name parameter", "Content-Type: text/plain; name=mail body.txt\r\n\r\nActual inline body", "Actual inline body"},
		{"usable HTML type with malformed name parameter", "Content-Type: text/html; name=mail body.html\r\n\r\n<p>Actual inline body</p>", "Actual inline body"},
		{"usable plain type with trailing semicolon", "Content-Type: text/plain; charset=utf-8;\r\n\r\nActual inline body", "Actual inline body"},
		{"HTML armored encrypted message", "Content-Type: text/html\r\n\r\n<div>-----BEGIN PGP MESSAGE-----</div><div>encrypted bytes</div><div>-----END PGP MESSAGE-----</div>", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MessagePreview(strings.NewReader(tc.raw)); got != tc.want {
				t.Errorf("MessagePreview() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMessagePreviewMIMEPartBudget(t *testing.T) {
	// Tiny empty parts amplify allocation and traversal work far beyond their
	// byte size. The root and all visited containers count toward the budget.
	emptyParts := make([]string, 127)
	for i := range emptyParts {
		emptyParts[i] = "\r\n"
	}
	parts := append(emptyParts, "Content-Type: text/plain\r\n\r\nBeyond the part budget")
	raw := previewMIMEMultipart("mixed", "many", parts...)
	if got := MessagePreview(strings.NewReader(raw)); got != "" {
		t.Errorf("MessagePreview() = %q, want no text beyond the part budget", got)
	}

	t.Run("HTML collected within budget remains usable", func(t *testing.T) {
		parts := append([]string{"Content-Type: text/html\r\n\r\n<p>HTML fallback</p>"}, emptyParts...)
		parts = append(parts, "Content-Type: text/plain\r\n\r\nBeyond the part budget")
		raw := previewMIMEMultipart("mixed", "many", parts...)
		if got := MessagePreview(strings.NewReader(raw)); got != "HTML fallback" {
			t.Errorf("MessagePreview() = %q, want HTML collected within budget", got)
		}
	})
}

func TestMessagePreviewDigestDefaults(t *testing.T) {
	plain := "Content-Type: text/plain\r\n\r\nActual inline body"
	messageBody := "From: sender@example.com\r\nSubject: Encapsulated message\r\nContent-Type: text/plain\r\n\r\nDigest message text"
	// The blank MIME part header leaves the Content-Type absent. The following
	// headers belong to the encapsulated message, not to the digest part itself.
	untypedMessage := "\r\n" + messageBody
	digest := previewMIMEMultipart("digest", "digest", untypedMessage)
	for _, tc := range []struct{ name, raw, want string }{
		{"implicit message falls through to body", previewMIMEMultipart("mixed", "mixed", digest, plain), "Actual inline body"},
		{"only implicit messages", digest, ""},
		{"explicit message remains unsupported", previewMIMEMultipart("digest", "digest", "Content-Type: message/rfc822\r\n\r\n"+messageBody), ""},
		{"explicit plain after implicit message", previewMIMEMultipart("digest", "digest", untypedMessage, plain), "Actual inline body"},
		{"explicit plain remains charset decoded", previewMIMEMultipart("digest", "digest", "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\ncaf=C3=A9"), "café"},
		{"digest default applies only to direct children", previewMIMEMultipart("digest", "digest", previewMIMEMultipart("mixed", "inner", "\r\nMixed default plain")), "Mixed default plain"},
		{"root absent type remains plain", "Subject: hello\r\n\r\nRoot default plain", "Root default plain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MessagePreview(strings.NewReader(tc.raw)); got != tc.want {
				t.Errorf("MessagePreview() = %q, want %q", got, tc.want)
			}
		})
	}
}
