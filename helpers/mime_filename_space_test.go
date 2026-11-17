package helpers

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-message"
	"github.com/migadu/go-imap"
)

func TestMIMEHeaderFilenameSpaces(t *testing.T) {
	for _, test := range []struct {
		name, raw, filename string
		complete            bool
	}{
		{"reported image", `inline; filename=Concur _1_.png`, "Concur _1_.png", true},
		{"case and following parameter", `INLINE; FILENAME=monthly report.pdf; size=12`, "monthly report.pdf", true},
		{"space runs", `inline; filename=monthly  report.pdf`, "monthly  report.pdf", true},
		{"syntactic whitespace", "inline; filename=\t monthly report.pdf \t; size=12", "monthly report.pdf", true},
		{"quoted scope", `inline; description="a;b\"c(d)"; filename=monthly report.pdf`, "monthly report.pdf", true},
		{"other quoted tab", "inline; description=\"a\tb\"; filename=monthly report.pdf", "monthly report.pdf", true},
		{"other quoted UTF-8", `inline; description="café"; filename=monthly report.pdf`, "monthly report.pdf", true},
		{"trailing separator", `inline; filename=monthly report.pdf;`, "monthly report.pdf", true},
		// The quoted forms of these are recognised but incomplete, so the
		// recovered forms are too.
		{"trailing separators", `inline; filename=monthly report.pdf;;`, "monthly report.pdf", false},
		{"spaced trailing separators", `inline; filename=monthly report.pdf; ;`, "monthly report.pdf", false},
		{"other parameter NBSP", "inline; size=\u00a012; filename=monthly report.pdf", "monthly report.pdf", false},
		{"other parameter MSIE duplicate", `inline; note="a\\b"; note="a\b"; filename=monthly report.pdf`, "monthly report.pdf", false},
		{"quoted control", `inline; filename="monthly report.pdf"`, "monthly report.pdf", true},
		{"quoted semicolon control", `inline; filename="monthly; report.pdf"`, "monthly; report.pdf", true},
		{"strict comments control", `inline (part); filename=(name)report.pdf`, "report.pdf", true},
		{"extended control", `inline; filename*=utf-8''monthly%20report.pdf`, "", true},
		{"other malformed parameter", `inline; filename=monthly report.pdf; broken`, "", false},
		{"other duplicate parameter", `inline; filename=monthly report.pdf; size=1; size=2`, "", false},
		{"duplicate plain", `inline; filename=monthly report.pdf; filename=other.pdf`, "", false},
		{"duplicate same malformed plain", `inline; filename=monthly report.pdf; filename=monthly report.pdf`, "", false},
		{"extended coexistence", `inline; filename=monthly report.pdf; filename*=utf-8''chosen.pdf`, "", false},
		{"continued coexistence", `inline; filename=monthly report.pdf; filename*0=chosen.pdf`, "", false},
		{"unknown extended family", `inline; filename=monthly report.pdf; filename*x=chosen.pdf`, "", false},
		{"comment after candidate", `inline; filename=monthly report.pdf (note)`, "", false},
		{"comment between words", `inline; filename=monthly (note) report.pdf`, "", false},
		{"comment before candidate", `inline; filename=(note)monthly report.pdf`, "", false},
		{"comment elsewhere", `inline (note); filename=monthly report.pdf`, "", false},
		{"unclosed comment", `inline; filename=monthly report.pdf; note=(unclosed`, "", false},
		{"unclosed quote", `inline; filename=monthly report.pdf; note="unclosed`, "", false},
		{"stray quote", `inline; filename=monthly report.pdf"`, "", false},
		{"missing separator", `inline; filename=monthly report.pdf size=12`, "", false},
		{"internal tab", "inline; filename=monthly\treport.pdf", "", false},
		{"slash", `inline; filename=folder/monthly report.pdf`, "", false},
		{"backslash", `inline; filename=folder\monthly report.pdf`, "", false},
		{"non ASCII", `inline; filename=café report.pdf`, "", false},
		{"raw control", "inline; filename=monthly \x00report.pdf", "", false},
		{"other quoted NUL", "inline; description=\"a\x00b\"; filename=monthly report.pdf", "", false},
		{"other quoted DEL", "inline; description=\"a\x7fb\"; filename=monthly report.pdf", "", false},
		{"other quoted CRLF", "inline; description=\"a\r\nb\"; filename=monthly report.pdf", "", false},
		{"other quoted invalid UTF-8", "inline; description=\"a\xffb\"; filename=monthly report.pdf", "", false},
		{"other escaped invalid UTF-8", "inline; description=\"a\\\xffb\"; filename=monthly report.pdf", "", false},
		{"other quoted surrogate", "inline; description=\"a\xed\xa0\x80b\"; filename=monthly report.pdf", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := parseMIMEHeader(test.raw, false)
			if got.complete != test.complete || got.params["filename"] != test.filename {
				t.Fatalf("parseMIMEHeader = complete:%v params:%v invalid:%v; want complete:%v filename:%q", got.complete, got.params, got.invalid, test.complete, test.filename)
			}
			if got.value != "inline" {
				t.Errorf("disposition = %q, want inline", got.value)
			}
		})
	}

	for _, raw := range []string{
		`text/plain; name=monthly report.txt`,
		`multipart/mixed; boundary=monthly report`,
		`text/plain; charset=utf 8`,
		`text/plain; filename=monthly report.txt`,
	} {
		if got := parseMIMEHeader(raw, true); got.complete {
			t.Errorf("Content-Type was repaired: %q = %+v", raw, got)
		}
	}
}

// A recovered filename must read exactly as the same field with the filename
// quoted: the repair may not make a malformed field more definitive.
func TestMIMEHeaderFilenameSpacesMatchQuoted(t *testing.T) {
	for _, test := range []struct{ raw, quoted string }{
		{`inline; filename=x y.png`, `inline; filename="x y.png"`},
		{`inline; filename=x y.png;`, `inline; filename="x y.png";`},
		{`inline; filename=x y.png;;`, `inline; filename="x y.png";;`},
		{`inline; filename=x y.png; ;`, `inline; filename="x y.png"; ;`},
		{"inline; filename=x y.png;\t;", "inline; filename=\"x y.png\";\t;"},
		{`inline; filename=x y.png; size=12;;`, `inline; filename="x y.png"; size=12;;`},
		{"inline; size=\u00a012; filename=x y.png", "inline; size=\u00a012; filename=\"x y.png\""},
		{`inline; note="a\\b"; note="a\b"; filename=x y.png`, `inline; note="a\\b"; note="a\b"; filename="x y.png"`},
		{"inline; filename=x y.png; note=\"a\"\u00a0", "inline; filename=\"x y.png\"; note=\"a\"\u00a0"},
	} {
		t.Run(test.raw, func(t *testing.T) {
			got, want := parseMIMEHeader(test.raw, false), parseMIMEHeaderStrict(test.quoted, false)
			if got.value != want.value || got.complete != want.complete ||
				fmt.Sprint(got.params) != fmt.Sprint(want.params) || fmt.Sprint(got.invalid) != fmt.Sprint(want.invalid) {
				t.Fatalf("parseMIMEHeader(%q) = %+v; quoted form %q = %+v", test.raw, got, test.quoted, want)
			}
		})
	}
}

func TestAttachmentKeywordFilenameSpaces(t *testing.T) {
	for _, test := range []struct{ name, disposition, want string }{
		{"reported inline image", `inline; filename=Concur _1_.png`, "$hasattachment"},
		{"trailing separators", `inline; filename=monthly report.png;;`, "$hasattachment"},
		{"other parameter NBSP", "inline; size=\u00a012; filename=monthly report.png", "$hasattachment"},
		{"other parameter MSIE duplicate", `inline; note="a\\b"; note="a\b"; filename=monthly report.png`, "$hasattachment"},
		{"ambiguous plain duplicate", `inline; filename=monthly report.png; filename=other.png`, ""},
		{"ambiguous comments", `inline; filename=monthly (note) report.png`, ""},
		{"missing separator", `inline; filename=monthly report.png size=12`, ""},
		{"invalid extended form", `inline; filename=monthly report.png; filename*=utf-8''bad%ZZ`, ""},
		{"empty extended form", `inline; filename=monthly report.png; filename*=utf-8''`, ""},
		{"valid extended evidence survives", `inline; filename=monthly report.png; filename*=utf-8''chosen.png`, "$hasattachment"},
		{"valid continuation evidence survives", `inline; filename=monthly report.png; filename*0=chosen.png`, "$hasattachment"},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := []byte("Content-Type: image/png\r\nContent-Disposition: " + test.disposition + "\r\n\r\nPNG")
			keyword, known := AttachmentKeyword(raw)
			if string(keyword) != test.want || known != (test.want != "") {
				t.Fatalf("AttachmentKeyword = %q, %v; want %q", keyword, known, test.want)
			}
		})
	}

	for _, test := range []struct{ name, disposition, want string }{
		{"related resource remains inline", `inline; filename=Concur _1_.png`, "$hasnoattachment"},
		{"related malformed other parameter", `inline; filename=Concur _1_.png; broken`, ""},
		{"related duplicate other parameter", `inline; filename=Concur _1_.png; size=1; size=2`, ""},
		{"related interior empty parameter", `inline; filename=Concur _1_.png;; size=12`, ""},
		{"related trailing separator", `inline; filename=Concur _1_.png;`, "$hasnoattachment"},
		{"related trailing separators", `inline; filename=Concur _1_.png;;`, ""},
		{"related spaced trailing separators", `inline; filename=Concur _1_.png; ;`, ""},
		{"related other parameter NBSP", "inline; size=\u00a012; filename=Concur _1_.png", ""},
		{"related other parameter MSIE duplicate", `inline; note="a\\b"; note="a\b"; filename=Concur _1_.png`, ""},
		{"related unclosed quote", `inline; filename=Concur _1_.png; note="unclosed`, ""},
		{"related trailing comment", `inline; filename=Concur _1_.png (note)`, ""},
		{"related raw control", "inline; filename=Concur \x00_1_.png", ""},
		{"related other quoted control", "inline; description=\"a\x00b\"; filename=Concur _1_.png", ""},
		{"related other invalid UTF-8", "inline; description=\"a\xffb\"; filename=Concur _1_.png", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := previewMIMEMultipart("related", "b",
				"Content-Type: text/html\r\n\r\n<p>Body</p>",
				"Content-Type: image/png\r\nContent-Disposition: "+test.disposition+"\r\n\r\nPNG")
			if keyword, known := AttachmentKeyword([]byte(raw)); string(keyword) != test.want || known != (test.want != "") {
				t.Fatalf("AttachmentKeyword = %q, %v; want %q", keyword, known, test.want)
			}
		})
	}

	t.Run("Content-Type name remains strict", func(t *testing.T) {
		raw := "Content-Type: image/png; name=Concur _1_.png\r\nContent-Disposition: inline\r\n\r\nPNG"
		if keyword, known := AttachmentKeyword([]byte(raw)); known {
			t.Fatalf("AttachmentKeyword = %q, %v; want unknown", keyword, known)
		}
	})

	for _, test := range []struct{ name, unquoted, quoted string }{
		{"other parameter NBSP", "inline; size=\u00a012; filename=x y.png", "inline; size=\u00a012; filename=\"x y.png\""},
		{"other parameter MSIE duplicate", `inline; note="a\\b"; note="a\b"; filename=x y.png`, `inline; note="a\\b"; note="a\b"; filename="x y.png"`},
	} {
		t.Run("BODYSTRUCTURE parity/"+test.name, func(t *testing.T) {
			raw := []byte("Content-Type: image/png\r\nContent-Disposition: " + test.unquoted + "\r\n\r\nPNG")
			quotedRaw := []byte("Content-Type: image/png\r\nContent-Disposition: " + test.quoted + "\r\n\r\nPNG")

			bs := ExtractBodyStructure(bytes.NewReader(raw))
			part, ok := bs.(*imap.BodyStructureSinglePart)
			if !ok {
				t.Fatalf("ExtractBodyStructure = %T, want *imap.BodyStructureSinglePart", bs)
			}
			if part.Filename() != "x y.png" {
				t.Fatalf("ExtractBodyStructure filename = %q, want %q", part.Filename(), "x y.png")
			}
			wantKeyword, wantKnown := AttachmentKeyword(quotedRaw)
			if wantKeyword != KeywordHasAttachment || !wantKnown {
				t.Fatalf("quoted AttachmentKeyword = %q, %v; want %q, true", wantKeyword, wantKnown, KeywordHasAttachment)
			}
			if gotKeyword, gotKnown := AttachmentKeyword(raw); gotKeyword != wantKeyword || gotKnown != wantKnown {
				t.Fatalf("AttachmentKeyword = %q, %v; want %q, %v", gotKeyword, gotKnown, wantKeyword, wantKnown)
			}
		})
	}
}

func TestFilenameSpacesTextDisposition(t *testing.T) {
	for _, disposition := range []string{"inline", "attachment"} {
		t.Run(disposition, func(t *testing.T) {
			raw := "Content-Type: text/plain; charset=utf-8\r\nContent-Disposition: " + disposition + "; filename=monthly report.txt\r\n\r\nReadable body"
			entity, err := message.Read(strings.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			if disposition == "inline" {
				want = "Readable body"
			}
			if text, err := FTSPlaintextBody(entity); err != nil || text != want {
				t.Errorf("FTSPlaintextBody = %q, %v; want %q", text, err, want)
			}
			if preview := MessagePreview(strings.NewReader(raw)); preview != want {
				t.Errorf("MessagePreview = %q; want %q", preview, want)
			}
		})
	}
}
