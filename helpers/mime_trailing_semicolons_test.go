package helpers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/emersion/go-message"
	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
)

// mime.ParseMediaType ignores one trailing ";" but rejects ";;" and "; ;" with
// no parameters. Every reader of the stored message must still see the charset
// and the boundary, as it does with one trailing ";" (#1802).
var trailingSemicolonSuffixes = []struct{ name, suffix string }{
	{"none", ""},
	{"one trailing semicolon", ";"},
	{"two trailing semicolons", ";;"},
	{"semicolon space semicolon", "; ;"},
}

func trailingSemicolonSinglePart(suffix string) string {
	return "From: a@example.com\r\nTo: b@example.com\r\nSubject: probe\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=iso-8859-1" + suffix + "\r\n" +
		"\r\n" +
		"caf\xe9 words\r\n" // "é" is the ISO-8859-1 octet 0xE9
}

func trailingSemicolonMultipart(suffix string) string {
	return "From: a@example.com\r\nTo: b@example.com\r\nSubject: probe\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=b1" + suffix + "\r\n" +
		"\r\n" +
		"--b1\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"hello words\r\n" +
		"--b1--\r\n"
}

func TestTrailingSemicolons_SinglePart(t *testing.T) {
	for _, tc := range trailingSemicolonSuffixes {
		t.Run(tc.name, func(t *testing.T) {
			raw := trailingSemicolonSinglePart(tc.suffix)

			entity, err := message.Read(strings.NewReader(raw))
			if err != nil {
				t.Fatalf("message.Read: %v", err)
			}
			text, err := ExtractPlaintextBody(entity)
			if err != nil || text == nil || strings.TrimSpace(*text) != "café words" {
				t.Errorf("ExtractPlaintextBody = %q (err %v), want \"café words\"", deref(text), err)
			}

			if got := MessagePreview(strings.NewReader(raw)); got != "café words" {
				t.Errorf("MessagePreview = %q, want \"café words\"", got)
			}

			bs, err := SafeBodyStructure([]byte(raw))
			if err != nil {
				t.Fatalf("SafeBodyStructure: %v", err)
			}
			leaf, ok := bs.(*imap.BodyStructureSinglePart)
			if !ok || leaf.Type != "text" || leaf.Subtype != "plain" || leaf.Params["charset"] != "iso-8859-1" {
				t.Errorf("BODYSTRUCTURE = %#v, want text/plain with charset=iso-8859-1", bs)
			}
		})
	}
}

func TestTrailingSemicolons_Multipart(t *testing.T) {
	for _, tc := range trailingSemicolonSuffixes {
		t.Run(tc.name, func(t *testing.T) {
			raw := trailingSemicolonMultipart(tc.suffix)

			entity, err := message.Read(strings.NewReader(raw))
			if err != nil {
				t.Fatalf("message.Read: %v", err)
			}
			text, err := ExtractPlaintextBody(entity)
			if err != nil || text == nil || *text != "hello words" {
				t.Errorf("ExtractPlaintextBody = %q (err %v), want \"hello words\"", deref(text), err)
			}

			if got := MessagePreview(strings.NewReader(raw)); got != "hello words" {
				t.Errorf("MessagePreview = %q, want \"hello words\"", got)
			}

			bs, err := SafeBodyStructure([]byte(raw))
			if err != nil {
				t.Fatalf("SafeBodyStructure: %v", err)
			}
			mp, ok := bs.(*imap.BodyStructureMultiPart)
			if !ok || mp.Subtype != "alternative" || len(mp.Children) != 1 {
				t.Fatalf("BODYSTRUCTURE = %#v, want multipart/alternative with one child", bs)
			}
			if leaf, ok := mp.Children[0].(*imap.BodyStructureSinglePart); !ok || leaf.Type != "text" || leaf.Subtype != "plain" || leaf.Size != uint32(len("hello words")) {
				t.Errorf("BODYSTRUCTURE child = %#v, want the 11-octet text/plain part", mp.Children[0])
			}

			section := &imap.FetchItemBodySection{Part: []int{1}}
			if got := imapserver.ExtractBodySection(bytes.NewReader([]byte(raw)), section); string(got) != "hello words" {
				t.Errorf("BODY[1] = %q, want \"hello words\"", got)
			}
		})
	}
}

// RFC 2045 §5.2 recommends the default, plain text, for a syntactically invalid
// Content-Type. A text part whose parameters do not parse even without trailing
// semicolons is indexed like the preview shows it, not dropped.
func TestExtractPlaintextBody_InvalidParametersKeepText(t *testing.T) {
	for _, tc := range []struct{ name, contentType, body string }{
		{"text/plain", "text/plain; charset=utf-8; format", "hello words\r\n"},
		{"text/html", "text/html; charset=utf-8; format", "<p>hello words</p>\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "From: a@example.com\r\nSubject: probe\r\nMIME-Version: 1.0\r\n" +
				"Content-Type: " + tc.contentType + "\r\n\r\n" + tc.body
			if got := MessagePreview(strings.NewReader(raw)); got != "hello words" {
				t.Fatalf("MessagePreview = %q, want \"hello words\"", got)
			}
			entity, err := message.Read(strings.NewReader(raw))
			if err != nil {
				t.Fatalf("message.Read: %v", err)
			}
			text, err := ExtractPlaintextBody(entity)
			if err != nil || text == nil || strings.TrimSpace(*text) != "hello words" {
				t.Errorf("ExtractPlaintextBody = %q (err %v), want \"hello words\"", deref(text), err)
			}
		})
	}
}

// A text part whose parameters do not parse is read without its charset, so
// it is only the text of last resort: a multipart/alternative whose text/plain
// part is malformed is indexed from its well-formed text/html alternative, as
// it is when the malformed part is skipped. Without a well-formed text part,
// the malformed one is still indexed.
func TestExtractPlaintextBody_InvalidParametersWellFormedAlternativeWins(t *testing.T) {
	for _, tc := range []struct{ name, plainType, htmlType, want string }{
		{"well-formed html alternative", "text/plain; charset=iso-8859-1; format", "text/html; charset=utf-8", "café words"},
		{"no well-formed alternative", "text/plain; charset=utf-8; format", "text/html; charset=utf-8; format", "plain words"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "From: a@example.com\r\nSubject: probe\r\nMIME-Version: 1.0\r\n" +
				"Content-Type: multipart/alternative; boundary=b1\r\n" +
				"\r\n" +
				"--b1\r\n" +
				"Content-Type: " + tc.plainType + "\r\n" +
				"\r\n" +
				strings.Replace(tc.want, "café", "caf\xe9", 1) + "\r\n" + // ISO-8859-1 octets
				"--b1\r\n" +
				"Content-Type: " + tc.htmlType + "\r\n" +
				"\r\n" +
				"<p>café words</p>\r\n" +
				"--b1--\r\n"
			entity, err := message.Read(strings.NewReader(raw))
			if err != nil {
				t.Fatalf("message.Read: %v", err)
			}
			text, err := ExtractPlaintextBody(entity)
			if err != nil || text == nil || strings.TrimSpace(*text) != tc.want {
				t.Errorf("ExtractPlaintextBody = %q (err %v), want %q", deref(text), err, tc.want)
			}
		})
	}
}
