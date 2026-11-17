package helpers

import (
	"strings"
	"testing"

	"github.com/emersion/go-message"
)

// HTML-only messages are indexed through ExtractPlaintextBody. Malformed HTML
// must not silently discard later words: the FTS vector cannot recover them.
func TestExtractPlaintextBodyMalformedHTMLPreservesText(t *testing.T) {
	tests := []struct {
		name string
		html string
		want []string
	}{
		{
			name: "raw less-than before digit and apostrophe",
			html: "<p>I <3 this, it's great.</p><p>Second paragraph, we're happy.</p><p>Third</p>",
			want: []string{"I <3 this, it's great.", "Second paragraph, we're happy.", "Third"},
		},
		{
			name: "raw less-than before dollar price",
			html: "<p>Price <$50 - don't miss</p><p>Line two</p>",
			want: []string{"Price <$50 - don't miss", "Line two"},
		},
		{
			name: "apostrophe in unquoted attribute",
			html: "<td width=50' >cell text</td><p>following</p>",
			want: []string{"cell text", "following"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := "From: a@example.com\r\nSubject: malformed HTML\r\nMIME-Version: 1.0\r\n" +
				"Content-Type: text/html; charset=utf-8\r\n\r\n" + tt.html + "\r\n"
			entity, err := message.Read(strings.NewReader(raw))
			if err != nil {
				t.Fatalf("message.Read: %v", err)
			}
			got, err := ExtractPlaintextBody(entity)
			if err != nil {
				t.Fatalf("ExtractPlaintextBody: %v", err)
			}
			if got == nil {
				t.Fatal("ExtractPlaintextBody returned no text")
			}
			for _, fragment := range tt.want {
				if !strings.Contains(*got, fragment) {
					t.Errorf("missing %q from extracted text %q", fragment, *got)
				}
			}
		})
	}
}
