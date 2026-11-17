package helpers

import (
	"strings"
	"testing"

	"github.com/emersion/go-message"
)

func assertExtractAndPreview(t *testing.T, raw, want string) {
	t.Helper()

	entity, err := message.Read(strings.NewReader(raw))
	if err != nil && !message.IsUnknownCharset(err) && !message.IsUnknownEncoding(err) {
		t.Fatalf("message.Read: %v", err)
	}

	text, extractErr := ExtractPlaintextBody(entity)
	if extractErr != nil {
		t.Errorf("ExtractPlaintextBody unexpected error: %v", extractErr)
	}
	got := strings.TrimSpace(deref(text))
	if want == "" {
		if text != nil {
			t.Errorf("ExtractPlaintextBody = %q, want <nil>", *text)
		}
	} else if text == nil || got != want {
		t.Errorf("ExtractPlaintextBody = %q, want %q", deref(text), want)
	}

	if preview := MessagePreview(strings.NewReader(raw)); preview != want {
		t.Errorf("MessagePreview = %q, want %q", preview, want)
	}
}

func TestExtractPlaintextBody_SkipsMultipartAttachments(t *testing.T) {
	const rfcHeader = "From: a@example.com\r\nTo: b@example.com\r\nSubject: probe\r\nMIME-Version: 1.0\r\n"

	for _, tc := range []struct {
		name, disposition, leafHeadersAndBody, outerBody, want string
	}{
		{
			name:               "alternative attachment before plain body",
			disposition:        "attachment; filename=notes.mime",
			leafHeadersAndBody: "Content-Type: text/plain\r\n\r\nAttached secret",
			outerBody:          "Content-Type: text/plain\r\n\r\nActual message",
			want:               "Actual message",
		},
		{
			name:               "inline leaf cannot override attachment multipart ancestor",
			disposition:        "attachment",
			leafHeadersAndBody: "Content-Type: text/plain\r\nContent-Disposition: inline\r\n\r\nAttached secret",
			outerBody:          "Content-Type: text/plain\r\n\r\nActual message",
			want:               "Actual message",
		},
		{
			name:               "attached plain text cannot override HTML body",
			disposition:        "attachment",
			leafHeadersAndBody: "Content-Type: text/plain\r\n\r\nAttached secret",
			outerBody:          "Content-Type: text/html\r\n\r\n<p>Actual message</p>",
			want:               "Actual message",
		},
		{
			name:               "attached HTML cannot shadow later inline HTML body",
			disposition:        "attachment",
			leafHeadersAndBody: "Content-Type: text/html\r\n\r\n<p>Attached secret</p>",
			outerBody:          "Content-Type: text/html\r\n\r\n<p>Actual message</p>",
			want:               "Actual message",
		},
		{
			name:               "attached HTML cannot become fallback without inline text",
			disposition:        "attachment",
			leafHeadersAndBody: "Content-Type: text/html\r\n\r\n<p>Attached secret</p>",
			outerBody:          "Content-Type: application/octet-stream\r\n\r\nBinary payload",
			want:               "",
		},
		{
			name:               "mixed-case attachment disposition with malformed filename parameter",
			disposition:        "AtTaChMeNt; filename=private notes.mime",
			leafHeadersAndBody: "Content-Type: text/plain\r\n\r\nAttached secret",
			outerBody:          "Content-Type: text/plain\r\n\r\nActual message",
			want:               "Actual message",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := rfcHeader +
				"Content-Type: multipart/mixed; boundary=outer\r\n\r\n" +
				"--outer\r\nContent-Type: multipart/alternative; boundary=attached\r\n" +
				"Content-Disposition: " + tc.disposition + "\r\n\r\n" +
				"--attached\r\n" + tc.leafHeadersAndBody + "\r\n" +
				"--attached--\r\n--outer\r\n" + tc.outerBody + "\r\n--outer--\r\n"
			assertExtractAndPreview(t, raw, tc.want)
		})
	}

	t.Run("root multipart attachment", func(t *testing.T) {
		raw := rfcHeader +
			"Content-Type: multipart/alternative; boundary=b\r\n" +
			"Content-Disposition: attachment\r\n\r\n" +
			"--b\r\nContent-Type: text/plain\r\nContent-Disposition: inline\r\n\r\nAttached secret\r\n--b--\r\n"
		assertExtractAndPreview(t, raw, "")
	})
}

func TestExtractPlaintextBody_DispositionDefaults(t *testing.T) {
	const rfcHeader = "From: a@example.com\r\nTo: b@example.com\r\nSubject: probe\r\nMIME-Version: 1.0\r\n"
	plain := "Content-Type: text/plain\r\n\r\nActual inline body"
	privateText := "Content-Type: text/plain\r\nContent-Disposition: x-private; filename=private.txt\r\n\r\nPrivate attachment"
	privateMultipart := "Content-Disposition: X-PRIVATE; filename=private.mime\r\n" +
		previewMIMEMultipart("alternative", "private", "Content-Type: text/plain\r\nContent-Disposition: inline\r\n\r\nPrivate attachment")

	for _, tc := range []struct {
		name, body, want string
	}{
		{
			name: "unknown text disposition",
			body: previewMIMEMultipart("mixed", "mixed", privateText, plain),
			want: "Actual inline body",
		},
		{
			name: "unknown multipart disposition",
			body: previewMIMEMultipart("mixed", "mixed", privateMultipart, plain),
			want: "Actual inline body",
		},
		{
			name: "unknown root text disposition",
			body: privateText,
			want: "",
		},
		{
			name: "unknown disposition with malformed parameters",
			body: previewMIMEMultipart("mixed", "mixed",
				"Content-Type: text/plain\r\nContent-Disposition: X-PRIVATE; filename=private note.txt\r\n\r\nPrivate attachment",
				plain),
			want: "Actual inline body",
		},
		{
			name: "malformed disposition without type",
			body: previewMIMEMultipart("mixed", "mixed",
				"Content-Type: text/plain\r\nContent-Disposition: ; filename=private.txt\r\n\r\nPrivate attachment",
				plain),
			want: "Actual inline body",
		},
		{
			name: "quoted attachment disposition",
			body: previewMIMEMultipart("mixed", "mixed",
				"Content-Type: text/plain\r\nContent-Disposition: \"attachment\"; filename=private.txt\r\n\r\nPrivate attachment",
				plain),
			want: "Actual inline body",
		},
		{
			name: "attachment with unclosed comment",
			body: previewMIMEMultipart("mixed", "mixed",
				"Content-Type: text/plain\r\nContent-Disposition: ATTACHMENT (unclosed\r\n\r\nPrivate attachment",
				plain),
			want: "Actual inline body",
		},
		{
			name: "attachment missing semicolon before parameter",
			body: previewMIMEMultipart("mixed", "mixed",
				"Content-Type: text/plain\r\nContent-Disposition: attachment filename=private.txt\r\n\r\nPrivate attachment",
				plain),
			want: "Actual inline body",
		},
		{
			name: "inline disposition with malformed parameters kept after unknown disposition",
			body: previewMIMEMultipart("mixed", "mixed",
				privateText,
				"Content-Type: text/plain\r\nContent-Disposition: INLINE; filename=inline note.txt\r\n\r\nInline body"),
			want: "Inline body",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertExtractAndPreview(t, rfcHeader+tc.body, tc.want)
		})
	}
}

func TestExtractPlaintextBody_MultipartDigestAndEncrypted(t *testing.T) {
	const rfcHeader = "From: a@example.com\r\nTo: b@example.com\r\nSubject: probe\r\nMIME-Version: 1.0\r\n"
	plain := "Content-Type: text/plain\r\n\r\nActual inline body"
	encapsulated := "From: sender@example.com\r\nSubject: Encapsulated message\r\nContent-Type: text/plain\r\n\r\nDigest message text"
	untypedDigestChild := "\r\n" + encapsulated
	digest := previewMIMEMultipart("digest", "digest", untypedDigestChild)
	encrypted := previewMIMEMultipart(`encrypted; protocol="application/pgp-encrypted"`, "enc",
		"Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1",
		"\r\nCiphertext octets without Content-Type")

	for _, tc := range []struct {
		name, body, want string
	}{
		{
			name: "untyped digest direct child falls through to outer plain body",
			body: previewMIMEMultipart("mixed", "mixed", digest, plain),
			want: "Actual inline body",
		},
		{
			name: "digest with only untyped message parts returns nil",
			body: digest,
			want: "",
		},
		{
			name: "untyped digest child skipped before explicit plain sibling",
			body: previewMIMEMultipart("digest", "digest", untypedDigestChild, plain),
			want: "Actual inline body",
		},
		{
			name: "digest default applies only to direct children so nested mixed keeps plain default",
			body: previewMIMEMultipart("digest", "digest",
				untypedDigestChild,
				previewMIMEMultipart("mixed", "inner", "\r\nMixed default plain")),
			want: "Mixed default plain",
		},
		{
			name: "multipart/encrypted root is skipped",
			body: encrypted,
			want: "",
		},
		{
			name: "multipart/encrypted skipped before outer plain sibling",
			body: previewMIMEMultipart("mixed", "mixed", encrypted, plain),
			want: "Actual inline body",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertExtractAndPreview(t, rfcHeader+tc.body, tc.want)
		})
	}
}

func TestExtractPlaintextBody_MultipartRelatedRoot(t *testing.T) {
	const rfcHeader = "From: a@example.com\r\nTo: b@example.com\r\nSubject: probe\r\nMIME-Version: 1.0\r\n"
	plain := "Content-Type: text/plain\r\n\r\nPlain root"
	html := "Content-Type: text/html\r\n\r\n<p>HTML root</p>"
	auxiliary := "Content-Type: text/plain\r\n\r\nAuxiliary text"
	identified := func(id, part string) string {
		return "Content-ID: " + id + "\r\n" + part
	}
	root := identified("<root@example.com>", html)

	for _, tc := range []struct {
		name, body, want string
	}{
		{
			name: "default first child HTML root is not overridden by later plain auxiliary",
			body: previewRelatedMultipart("related", "text/html", "", html, auxiliary),
			want: "HTML root",
		},
		{
			name: "start parameter selects later Content-ID root over earlier plain auxiliary",
			body: previewRelatedMultipart("related", "text/html", "<root@example.com>", auxiliary, root),
			want: "HTML root",
		},
		{
			name: "start parameter trims whitespace and ignores duplicate Content-ID",
			body: previewRelatedMultipart("related", "text/html", " <root@example.com> ",
				identified(" \t<root@example.com> \t", html),
				identified("<root@example.com>", auxiliary)),
			want: "HTML root",
		},
		{
			name: "missing start root returns nil without falling back to auxiliary",
			body: previewRelatedMultipart("related", "text/html", "<missing@example.com>", auxiliary, root),
			want: "",
		},
		{
			name: "empty start parameter does not select child without Content-ID",
			body: strings.Replace(previewRelatedMultipart("related", "text/html", "", auxiliary), "; boundary=", `; start=""; boundary=`, 1),
			want: "",
		},
		{
			name: "selected root attachment disposition is ignored per RFC 2387 section 4",
			body: previewRelatedMultipart("related", "text/html", "<root@example.com>",
				identified("<root@example.com>", "Content-Disposition: attachment\r\n"+html),
				auxiliary),
			want: "HTML root",
		},
		{
			name: "selected root unknown disposition is ignored while grandchild disposition applies",
			body: previewRelatedMultipart("related", "multipart/alternative", "<root@example.com>",
				identified("<root@example.com>", "Content-Disposition: x-private\r\n"+
					previewMIMEMultipart("alternative", "alternative", "Content-Disposition: attachment\r\n"+auxiliary, html)),
				auxiliary),
			want: "HTML root",
		},
		{
			name: "outer attachment ancestor still excludes multipart/related subtree",
			body: previewMIMEMultipart("mixed", "mixed",
				"Content-Disposition: attachment\r\n"+previewRelatedMultipart("related", "text/plain", "<root@example.com>", identified("<root@example.com>", plain)),
				"Content-Type: text/plain\r\n\r\nOuter plain body"),
			want: "Outer plain body",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertExtractAndPreview(t, rfcHeader+tc.body, tc.want)
		})
	}

	t.Run("default root with unknown transfer encoding does not fall back to auxiliary", func(t *testing.T) {
		raw := rfcHeader + previewRelatedMultipart("related", "text/plain", "",
			"Content-Type: text/plain\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nencoded root",
			auxiliary)
		entity, err := message.Read(strings.NewReader(raw))
		if err != nil {
			t.Fatalf("message.Read: %v", err)
		}
		text, extractErr := ExtractPlaintextBody(entity)
		if text != nil {
			t.Errorf("ExtractPlaintextBody = %q (err %v), want <nil>", *text, extractErr)
		}
		if extractErr == nil {
			t.Errorf("ExtractPlaintextBody err = nil, want skipped error for unknown encoding")
		}
		if preview := MessagePreview(strings.NewReader(raw)); preview != "" {
			t.Errorf("MessagePreview = %q, want \"\"", preview)
		}
	})
}

func TestExtractPlaintextBody_RelatedContentIDCFWS(t *testing.T) {
	for _, tc := range []struct {
		name, start, contentID, want string
	}{
		{"leading comment", "<root@example.com>", "(selected) <root@example.com>", "Root words"},
		{"trailing nested comment", "<root@example.com>", "<root@example.com> (selected (root))", "Root words"},
		{"folded surrounding comments", "<root@example.com>", "(selected)\r\n \t<root@example.com> (root)", "Root words"},
		{"comments in start", "(selected) <root@example.com> (root)", "<root@example.com>", "Root words"},
		{"domain literal contains closing angle", "<root@[example>domain]>", "(selected) <root@[example>domain]> (root >)", "Root words"},
		{"quoted local contains closing angle", `<"root>name"@example.com>`, `(selected) <"root>name"@example.com> (root >)`, "Root words"},
		{"escaped quote in local", `<"root\">name"@example.com>`, `(selected) <"root\">name"@example.com> (root)`, "Root words"},
		{"case remains significant", "<Root@example.com>", "(selected) <root@example.com>", ""},
		{"multiple identifiers are not one Content-ID", "<root@example.com>", "<resource@example.com> <root@example.com>", ""},
		{"unclosed comment remains invalid", "<root@example.com>", "<root@example.com> (unclosed", ""},
		{"trailing garbage remains invalid", "<root@example.com>", "<root@example.com> extra", ""},
		{"legacy exact identifier is retained", "<logo>", "<logo>", "Root words"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "MIME-Version: 1.0\r\n" + previewRelatedMultipart("related", "text/plain", tc.start,
				"Content-Type: text/plain\r\nContent-ID: <resource@example.com>\r\n\r\nAuxiliary words",
				"Content-Type: text/plain\r\nContent-ID: "+tc.contentID+"\r\n\r\nRoot words",
				"Content-Type: text/plain\r\nContent-ID: <root@example.com>\r\n\r\nDuplicate words")
			// A duplicate ID must not let an invalid or mismatched root select
			// the later child in the negative cases.
			if tc.want == "" {
				raw = strings.Replace(raw, "Content-ID: <root@example.com>\r\n\r\nDuplicate words", "Content-ID: <duplicate@example.com>\r\n\r\nDuplicate words", 1)
			}
			assertExtractAndPreview(t, raw, tc.want)
		})
	}
}
