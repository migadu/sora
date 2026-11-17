package helpers

import (
	"strings"
	"testing"

	"github.com/emersion/go-message"
)

// The tsvector is the only copy of a body's text, so text the extraction drops
// at delivery can never be searched.
func TestFTSPlaintextBodyKeepsTextAfterParserLimits(t *testing.T) {
	longLine := strings.Repeat("a", 5000) + " TAILMARKER " + strings.Repeat("b", 5000)
	for _, test := range []struct {
		name, header, body, want string
	}{
		{
			// The stdlib quoted-printable reader stops at a 4096-byte physical line.
			name:   "quoted-printable line over 4 KB",
			header: "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n",
			body:   longLine + "\r\n",
			want:   "TAILMARKER",
		},
		{
			// Common in Outlook HTML: attributes on their own lines.
			name:   "HTML link attributes on new lines",
			header: "Content-Type: text/html; charset=utf-8\r\n",
			body:   "<p>Hello</p><a\r\nhref=\"https://example.com/a\"\r\nstyle=\"x\">Link</a> then the body continues TAILMARKER.\r\n",
			want:   "TAILMARKER",
		},
		{
			name:   "HTML stray closing tag",
			header: "Content-Type: text/html; charset=utf-8\r\n",
			body:   "<p>a</p></a><p>after the stray close TAILMARKER</p>\r\n",
			want:   "TAILMARKER",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw := "From: a@example.com\r\nSubject: s\r\nMIME-Version: 1.0\r\n" + test.header + "\r\n" + test.body
			entity, err := message.Read(strings.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			text, err := FTSPlaintextBody(entity)
			if err != nil {
				t.Fatalf("FTSPlaintextBody error: %v", err)
			}
			if !strings.Contains(text, test.want) {
				t.Fatalf("FTSPlaintextBody dropped %q: got %d bytes ending %q", test.want, len(text), text[max(0, len(text)-80):])
			}
		})
	}
}
