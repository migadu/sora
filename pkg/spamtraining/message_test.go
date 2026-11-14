package spamtraining

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset"
)

// parseTrainingCopy parses a StripAttachments result the way the training
// service's MIME parser would: it returns the media type of every entity in
// tree order and the decoded text of every text/* leaf.
func parseTrainingCopy(t *testing.T, raw []byte) (types, texts []string) {
	t.Helper()
	entity, err := message.Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("training copy does not parse: %v\n%s", err, raw)
	}
	err = entity.Walk(func(_ []int, part *message.Entity, err error) error {
		if err != nil {
			return err
		}
		mediaType, _, _ := part.Header.ContentType()
		types = append(types, mediaType)
		if strings.HasPrefix(mediaType, "text/") {
			b, err := io.ReadAll(part.Body)
			if err != nil {
				return fmt.Errorf("%s part does not decode: %w", mediaType, err)
			}
			texts = append(texts, string(b))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking training copy: %v\n%s", err, raw)
	}
	return types, texts
}

func crlf(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") }

const pdfPart = `--outer
Content-Type: application/pdf
Content-Transfer-Encoding: base64

JVBERi0=
--outer--
`

// nestedLatin1 is the layout of any message with an attachment: the text sits
// in a multipart/alternative below the top-level multipart/mixed.
const nestedLatin1 = `From: a@example.org
To: user@example.com
Subject: test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: multipart/alternative; boundary="inner"

--inner
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: base64

U2No9m4=
--inner--
` + pdfPart

const topLevelLatin1 = `From: a@example.org
To: user@example.com
Subject: test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: text/plain; charset=iso-8859-1
Content-Transfer-Encoding: base64

U2No9m4=
` + pdfPart

const alternativeWithImage = `From: a@example.org
To: user@example.com
Subject: test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

preamble
--outer
Content-Type: multipart/alternative; boundary="inner"

--inner
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

Caf=C3=A9
--inner
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: base64

PHA+Q2Fmw6k8L3A+
--inner--
--outer
Content-Type: image/png
Content-Transfer-Encoding: base64

iVBORw0K
--outer--
epilogue
`

// digestOfMessages is a digest whose part has no Content-Type: RFC 2046
// §5.1.1 makes it message/rfc822, a whole message, not a text part.
const digestOfMessages = `From: a@example.org
To: user@example.com
Subject: test
MIME-Version: 1.0
Content-Type: multipart/digest; boundary="outer"

--outer

From: b@example.org
Subject: forwarded
MIME-Version: 1.0
Content-Type: application/pdf
Content-Transfer-Encoding: base64

JVBERi0=
--outer--
`

const attachmentOnly = `From: a@example.org
To: user@example.com
Subject: test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

` + pdfPart

// brokenNested holds a well-formed text part next to two nested multiparts
// that do not parse, one without a boundary parameter and one without its
// close delimiter. The old code never descended into either, so they cannot
// be allowed to fail the whole message: the caller would then send the
// original, attachment included.
const brokenNested = `From: a@example.org
To: user@example.com
Subject: test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="outer"

--outer
Content-Type: multipart/alternative

junk
--outer
Content-Type: multipart/alternative; boundary="inner"

--inner
Content-Type: text/html

<p>cut off</p>
--outer
Content-Type: text/plain

hello
` + pdfPart

func TestStripAttachments(t *testing.T) {
	tests := []struct {
		name      string
		msg       string
		wantTypes []string
		wantTexts []string
	}{
		{
			name:      "text nested below multipart/mixed",
			msg:       crlf(nestedLatin1),
			wantTypes: []string{"multipart/mixed", "multipart/alternative", "text/plain"},
			wantTexts: []string{"Schön"},
		},
		{
			name:      "text nested below multipart/mixed, bare LF line endings",
			msg:       nestedLatin1,
			wantTypes: []string{"multipart/mixed", "multipart/alternative", "text/plain"},
			wantTexts: []string{"Schön"},
		},
		{
			name:      "encoded text part directly below multipart/mixed",
			msg:       crlf(topLevelLatin1),
			wantTypes: []string{"multipart/mixed", "text/plain"},
			wantTexts: []string{"Schön"},
		},
		{
			// RFC 2046 §5.1.4: the parts of a multipart/alternative are
			// versions of the same content, so they must stay one.
			name:      "alternative keeps both versions and its structure",
			msg:       crlf(alternativeWithImage),
			wantTypes: []string{"multipart/mixed", "multipart/alternative", "text/plain", "text/html"},
			wantTexts: []string{"Café", "<p>Café</p>"},
		},
		{
			name:      "no text part anywhere",
			msg:       crlf(attachmentOnly),
			wantTypes: []string{"text/plain"},
			wantTexts: []string{"[No text content - attachments stripped for spam training]\n"},
		},
		{
			name:      "untyped digest part is a message, not text",
			msg:       crlf(digestOfMessages),
			wantTypes: []string{"text/plain"},
			wantTexts: []string{"[No text content - attachments stripped for spam training]\n"},
		},
		{
			name:      "nested multipart that does not parse is dropped",
			msg:       crlf(brokenNested),
			wantTypes: []string{"multipart/mixed", "text/plain"},
			wantTexts: []string{"hello"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := StripAttachments([]byte(tt.msg))
			if err != nil {
				t.Fatalf("StripAttachments: %v", err)
			}
			for _, attachment := range []string{"JVBERi0", "iVBORw0K"} {
				if bytes.Contains(out, []byte(attachment)) {
					t.Errorf("training copy still carries attachment data %q:\n%s", attachment, out)
				}
			}
			if !bytes.Contains(out, []byte("Subject: test")) {
				t.Errorf("training copy lost the message header:\n%s", out)
			}
			types, texts := parseTrainingCopy(t, out)
			if !reflect.DeepEqual(types, tt.wantTypes) {
				t.Errorf("parts = %q, want %q\n%s", types, tt.wantTypes, out)
			}
			if !reflect.DeepEqual(texts, tt.wantTexts) {
				t.Errorf("texts = %q, want %q\n%s", texts, tt.wantTexts, out)
			}
		})
	}
}

// TestStripAttachmentsBoundsNesting checks that a pathologically deep
// multipart tree is not followed to the bottom: every level holds its own
// parser buffer, so the walk stops at a fixed depth and drops what is below,
// while text above that depth is still kept.
func TestStripAttachmentsBoundsNesting(t *testing.T) {
	const levels = 1000
	var b strings.Builder
	b.WriteString("Subject: deep\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b0\"\r\n\r\n")
	b.WriteString("--b0\r\nContent-Type: text/plain\r\n\r\nshallow\r\n")
	for i := 0; i < levels; i++ {
		fmt.Fprintf(&b, "--b%d\r\nContent-Type: multipart/mixed; boundary=\"b%d\"\r\n\r\n", i, i+1)
	}
	fmt.Fprintf(&b, "--b%d\r\nContent-Type: text/plain\r\n\r\ndeep\r\n--b%d--\r\n", levels, levels)
	for i := levels - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "--b%d--\r\n", i)
	}

	out, err := StripAttachments([]byte(b.String()))
	if err != nil {
		t.Fatalf("StripAttachments: %v", err)
	}
	_, texts := parseTrainingCopy(t, out)
	if !reflect.DeepEqual(texts, []string{"shallow"}) {
		t.Errorf("texts = %q, want only the shallow part", texts)
	}
}
