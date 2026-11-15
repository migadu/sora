package helpers

import (
	"io"
	"strings"
	"testing"

	"github.com/emersion/go-message"
	"github.com/migadu/go-imap"
)

// RFC 2045 §5.1 inherits RFC 822 comments and quoted-pairs. Comments have no
// semantic content; neither their semicolons nor quotes introduce parameters.
func TestAttachmentKeyword_RFCMIMEComments(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body string
		want                    string
	}{
		{"comment cannot supply a filename", `text/plain; charset=us-ascii (notes; name=report.pdf; more)`, "body", "$hasnoattachment"},
		{"nested comment cannot supply a filename", `text/plain; charset=us-ascii (outer (notes; name=report.pdf; more) tail)`, "body", "$hasnoattachment"},
		{"escaped parenthesis stays inside comment", `text/plain; charset=us-ascii (notes \) still comment; name=report.pdf; more)`, "body", "$hasnoattachment"},
		{"quote inside comment is not syntax", `text/plain; charset=us-ascii (notes "abc; name=report.pdf; "more)`, "body", "$hasnoattachment"},
		{"comment before a name", `application/pdf; (notes) name=report.pdf`, "PDF", "$hasattachment"},
		{"comment after a name", `application/pdf; name=report.pdf (notes)`, "PDF", "$hasattachment"},
		{"comment after multipart type", `multipart/mixed (notes); boundary=b`, "--b\r\nContent-Disposition: attachment\r\n\r\nPDF\r\n--b--\r\n", "$hasattachment"},
		{"comment after boundary", `multipart/mixed; boundary=b (notes; "name=fake.pdf"; (more))`, "--b\r\nContent-Disposition: attachment\r\n\r\nPDF\r\n--b--\r\n", "$hasattachment"},
		{"parentheses inside quoted boundary are literal", `multipart/mixed; boundary="b(notes)"`, "--b(notes)\r\nContent-Disposition: attachment\r\n\r\nPDF\r\n--b(notes)--\r\n", "$hasattachment"},
		{"quoted pair in boundary escapes an ordinary character", `multipart/mixed; boundary="b\c"`, "--bc\r\nContent-Disposition: attachment\r\n\r\nPDF\r\n--bc--\r\n", "$hasattachment"},
		{"unclosed comment makes the remaining text untrustworthy", `text/plain; charset=us-ascii (notes; name=report.pdf; more`, "body", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyword, known := AttachmentKeyword([]byte("Content-Type: " + tc.contentType + "\r\n\r\n" + tc.body))
			if string(keyword) != tc.want || known != (tc.want != "") {
				t.Fatalf("AttachmentKeyword = %q, %v; want %q", keyword, known, tc.want)
			}
		})
	}
}

func TestAttachmentKeyword_AmbiguousParameterQuotes(t *testing.T) {
	for _, disposition := range []string{
		`inline; x="unclosed; description="notes; filename=report.pdf`,
		`inline; x=foo"bar; description="notes; filename=report.pdf; y="`,
		`inline; x="closed"junk; filename=report.pdf`,
	} {
		t.Run(disposition, func(t *testing.T) {
			keyword, known := AttachmentKeyword([]byte("Content-Type: application/pdf\r\nContent-Disposition: " + disposition + "\r\n\r\nPDF"))
			if known {
				t.Fatalf("ambiguous parameter quoting yielded %q; want unknown", keyword)
			}
		})
	}
}

func TestAttachmentKeyword_RFCBoundaryParameters(t *testing.T) {
	for _, tc := range []struct {
		name, params, boundary string
		want                   string
	}{
		{"RFC2231 extended", `boundary*=us-ascii''b`, "b", "$hasattachment"},
		{"RFC2231 unspecified charset", `boundary*=''b`, "b", "$hasattachment"},
		{"RFC2231 continued", `boundary*0="outer"; boundary*1="123"`, "outer123", "$hasattachment"},
		{"RFC2231 continued out of order", `boundary*1=123; boundary*0=outer`, "outer123", "$hasattachment"},
		{"RFC2231 continued with unrelated bad param", `boundary*0="outer"; boundary*1="123"; type=text/html`, "outer123", "$hasattachment"},
		{"valid boundary before ambiguous value", `boundary=b; x=foo"bar`, "b", "$hasattachment"},
		{"boundary after ambiguous value is untrustworthy", `x=foo"bar; boundary=b`, "b", ""},
		{"conflicting duplicate boundary", `boundary=b; boundary=c`, "b", ""},
		{"matching duplicate boundary", `boundary=b; boundary=b`, "b", "$hasattachment"},
		{"valid extended takes precedence", `boundary=legacy; boundary*=us-ascii''b`, "b", "$hasattachment"},
		{"conflicting selected extended boundary", `boundary=b; boundary*=us-ascii''a; boundary*=us-ascii''b`, "b", ""},
		{"boundary length limit", `boundary="` + strings.Repeat("b", 70) + `"`, strings.Repeat("b", 70), "$hasattachment"},
		{"boundary over 70 octets is used verbatim", `boundary="` + strings.Repeat("b", 71) + `"`, strings.Repeat("b", 71), "$hasattachment"},
		{"leading space is permitted", `boundary=" b"`, " b", "$hasattachment"},
		{"interior space is permitted", `boundary="b b"`, "b b", "$hasattachment"},
		{"boundary punctuation is permitted", `boundary="b'()+_,-./:=?b"`, "b'()+_,-./:=?b", "$hasattachment"},
		{"trailing space is used verbatim", `boundary="b "`, "b ", "$hasattachment"},
		{"tab is used verbatim", "boundary=\"b\tb\"", "b\tb", "$hasattachment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "Content-Type: multipart/mixed; " + tc.params + "\r\n\r\n--" + tc.boundary +
				"\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment\r\n\r\nPDF\r\n--" + tc.boundary + "--\r\n"
			keyword, known := AttachmentKeyword([]byte(raw))
			if string(keyword) != tc.want || known != (tc.want != "") {
				t.Fatalf("AttachmentKeyword = %q, %v; want %q", keyword, known, tc.want)
			}
		})
	}
}

func TestAttachmentKeyword_EvidenceBeforeAmbiguousParameter(t *testing.T) {
	for _, raw := range []string{
		"Content-Type: application/pdf; name=report.pdf; x=foo\"bar\r\n\r\nPDF",
		"Content-Type: application/pdf\r\nContent-Disposition: inline; filename=report.pdf; x=foo\"bar\r\n\r\nPDF",
	} {
		keyword, known := AttachmentKeyword([]byte(raw))
		if !known || keyword != KeywordHasAttachment {
			t.Fatalf("valid filename before ambiguous parameter yielded %q, %v; want attachment", keyword, known)
		}
	}
}

// RFC 2045 §1: MIME header fields "can include RFC 822 comments, which have no
// semantic content and should be ignored during MIME processing", so a
// Content-Transfer-Encoding with comments is the mechanism it names, for the
// stored BODYSTRUCTURE, the full-text search text and the PREVIEW alike.
var cteCommentMessages = []struct {
	name, raw, wantEncoding, wantText string
}{
	{
		name: "single part",
		raw: "From: a@example.com\r\nTo: b@example.com\r\nSubject: comment\r\nMIME-Version: 1.0\r\n" +
			"Content-Type: text/plain\r\n" +
			"Content-Transfer-Encoding: base64 (encoded)\r\n" +
			"\r\n" +
			"aGVsbG8gd29ybGQK\r\n",
		wantEncoding: "base64",
		wantText:     "hello world\n",
	},
	{
		name: "multipart child",
		raw: "From: a@example.com\r\nTo: b@example.com\r\nSubject: comment\r\nMIME-Version: 1.0\r\n" +
			"Content-Type: multipart/alternative; boundary=b\r\n" +
			"\r\n" +
			"--b\r\n" +
			"Content-Type: text/plain; charset=utf-8\r\n" +
			"Content-Transfer-Encoding: (a (nested) comment) Quoted-Printable (with a \\) quoted-pair)\r\n" +
			"\r\n" +
			"hello wor=\r\nld=21\r\n" +
			"--b--\r\n",
		wantEncoding: "quoted-printable",
		wantText:     "hello world!",
	},
}

func TestCTEComments_BodyStructure(t *testing.T) {
	for _, tc := range cteCommentMessages {
		t.Run(tc.name, func(t *testing.T) {
			bs, err := SafeBodyStructure([]byte(tc.raw))
			if err != nil {
				t.Fatalf("SafeBodyStructure: %v", err)
			}
			if mp, ok := bs.(*imap.BodyStructureMultiPart); ok {
				bs = mp.Children[0]
			}
			leaf, ok := bs.(*imap.BodyStructureSinglePart)
			if !ok {
				t.Fatalf("leaf is %T, want *imap.BodyStructureSinglePart", bs)
			}
			if !strings.EqualFold(leaf.Encoding, tc.wantEncoding) {
				t.Errorf("body-fld-enc = %q, want %q", leaf.Encoding, tc.wantEncoding)
			}
		})
	}
}

func TestCTEComments_ExtractPlaintextBody(t *testing.T) {
	for _, tc := range cteCommentMessages {
		t.Run(tc.name, func(t *testing.T) {
			// server.ParseMessage tolerates an unknown encoding the same way.
			entity, err := message.Read(strings.NewReader(tc.raw))
			if err != nil && !message.IsUnknownEncoding(err) {
				t.Fatalf("message.Read: %v", err)
			}
			text, err := ExtractPlaintextBody(entity)
			if err != nil {
				t.Errorf("ExtractPlaintextBody error: %v", err)
			}
			if text == nil || strings.TrimRight(*text, "\r\n") != strings.TrimRight(tc.wantText, "\r\n") {
				t.Errorf("ExtractPlaintextBody = %q, want %q", deref(text), tc.wantText)
			}
		})
	}
}

func TestCTEComments_MessagePreview(t *testing.T) {
	for _, tc := range cteCommentMessages {
		t.Run(tc.name, func(t *testing.T) {
			want := strings.TrimSpace(tc.wantText)
			if got := MessagePreview(strings.NewReader(tc.raw)); got != want {
				t.Errorf("MessagePreview = %q, want %q", got, want)
			}
		})
	}
}

func TestCTEComments_DecodeToBinary(t *testing.T) {
	var h message.Header
	h.Set("Content-Transfer-Encoding", "(encoded) BASE64 (as stored)")
	r, err := DecodeToBinary(&message.Entity{Header: h, Body: strings.NewReader("aGVsbG8gd29ybGQK")})
	if err != nil {
		t.Fatalf("DecodeToBinary: %v", err)
	}
	if b, err := io.ReadAll(r); err != nil || string(b) != "hello world\n" {
		t.Errorf("DecodeToBinary = %q, %v; want %q", b, err, "hello world\n")
	}

	// A comment is not part of the mechanism and separates tokens.
	for _, enc := range []string{"x-uuencode (comment)", "base(comment)64"} {
		h.Set("Content-Transfer-Encoding", enc)
		if _, err := DecodeToBinary(&message.Entity{Header: h, Body: strings.NewReader("")}); err == nil {
			t.Errorf("DecodeToBinary(%q): expected an unsupported-encoding error", enc)
		}
	}
}

func TestCTEComments_DefaultEncodingAndMalformedValues(t *testing.T) {
	for _, encoding := range []string{"", "(only a comment)", "(outer (nested) comment)"} {
		t.Run("identity "+encoding, func(t *testing.T) {
			const body = "plain body\r\n"
			var h message.Header
			h.Set("Content-Transfer-Encoding", encoding)
			r, err := DecodeToBinary(&message.Entity{Header: h, Body: strings.NewReader(body)})
			if err != nil {
				t.Fatalf("missing mechanism defaults to 7bit: %v", err)
			}
			if got, err := io.ReadAll(r); err != nil || string(got) != body {
				t.Fatalf("identity body = %q, %v", got, err)
			}
		})
	}

	// A comment separates tokens; it cannot make two tokens into one known
	// encoding. Malformed values likewise must not expose undecoded bytes in
	// PREVIEW, even if the MIME reader tolerates an unfinished comment.
	for _, encoding := range []string{"base(comment)64", "base64 (unfinished", "base64 (escaped\\)", "base64 extra", "base64;", "x-unknown (comment)"} {
		t.Run("unsupported "+encoding, func(t *testing.T) {
			const body = "aGVsbG8gd29ybGQK\r\n"
			var h message.Header
			h.Set("Content-Transfer-Encoding", encoding)
			if _, err := DecodeToBinary(&message.Entity{Header: h, Body: strings.NewReader(body)}); err == nil {
				t.Fatal("unsupported or malformed encoding was accepted")
			}
			raw := "Content-Type: text/plain\r\nContent-Transfer-Encoding: " + encoding + "\r\n\r\n" + body
			if got := MessagePreview(strings.NewReader(raw)); got != "" {
				t.Fatalf("unsupported or malformed preview = %q", got)
			}
		})
	}
}

func TestCTEComments_PreviewMatchesReaderForWhitespace(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		decoded     bool
	}{
		{"retained bare CR", "base64 \r \r\n", false},
		{"ordinary whitespace", "base64 \t\r\n", true},
		{"folded whitespace", "base64\r\n \t\r\n", true},
		{"folded comment", "(encoded)\r\n BASE64 (comment)\r\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const body = "aGVsbG8gd29ybGQK\r\n"
			raw := "Content-Type: text/plain\r\nContent-Transfer-Encoding: " + tc.field + "\r\n" + body
			entity, err := message.Read(strings.NewReader(raw))
			if tc.decoded && err != nil {
				t.Fatalf("valid CTE not decoded: %v", err)
			}
			if !tc.decoded && !message.IsUnknownEncoding(err) {
				t.Fatalf("malformed CTE was not reported as unknown: %v", err)
			}
			got, err := io.ReadAll(entity.Body)
			if err != nil {
				t.Fatal(err)
			}
			wantBody, wantPreview := body, ""
			if tc.decoded {
				wantBody, wantPreview = "hello world\n", "hello world"
			}
			if string(got) != wantBody {
				t.Fatalf("reader body = %q, want %q", got, wantBody)
			}
			if preview := MessagePreview(strings.NewReader(raw)); preview != wantPreview {
				t.Fatalf("preview = %q, want %q", preview, wantPreview)
			}
		})
	}
}

// FuzzTransferEncodingMechanismAgreesWithGoMessage pins the property PREVIEW
// relies on against go-message itself: every value transferEncodingMechanism
// reduces to a mechanism go-message knows is one go-message decodes.
func FuzzTransferEncodingMechanismAgreesWithGoMessage(f *testing.F) {
	for _, seed := range []string{
		"base64", "BASE64 (encoded)", "(a (nested) comment) Quoted-Printable (with a \\) quoted-pair)",
		"(only a comment)", "base64 (unclosed", "base(comment)64", "\rbase64", "base64\r ",
		" base64", "base64\r\n (folded)", "7bit\t", "x-uuencode (comment)",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, cte string) {
		switch transferEncodingMechanism(cte) {
		case "", "7bit", "8bit", "binary", "quoted-printable", "base64":
		default:
			return
		}
		var h message.Header
		h.Set("Content-Transfer-Encoding", cte)
		if _, err := message.New(h, strings.NewReader("")); message.IsUnknownEncoding(err) {
			t.Errorf("transferEncodingMechanism(%q) = %q, but go-message: %v", cte, transferEncodingMechanism(cte), err)
		}
	})
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
