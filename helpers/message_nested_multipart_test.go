package helpers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/emersion/go-message"
)

// A broken nested multipart cannot yield more parts of its own, but its parent
// multipart can still advance to later sibling parts, just as MessagePreview
// does (#1815).
func TestExtractPlaintextBody_BrokenNestedMultipart(t *testing.T) {
	const rfcHeader = "From: a@example.com\r\nTo: b@example.com\r\nSubject: probe\r\nMIME-Version: 1.0\r\n"

	tests := []struct {
		name        string
		body        string
		want        string
		wantSkipped bool
	}{
		{
			name: "well-formed nested multipart control",
			body: "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
				"--b\r\nContent-Type: multipart/alternative; boundary=c\r\n\r\n" +
				"--c\r\nContent-Type: text/html\r\n\r\n<p>inner html</p>\r\n" +
				"--c--\r\n" +
				"--b\r\nContent-Type: text/plain\r\n\r\nouter words\r\n" +
				"--b--\r\n",
			want: "outer words",
		},
		{
			name: "broken top-level multipart stops both",
			body: "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
				"--b\r\nBad header line\r\n\r\nx\r\n" +
				"--b\r\nContent-Type: text/plain\r\n\r\nouter words\r\n" +
				"--b--\r\n",
			want:        "",
			wantSkipped: true,
		},
		{
			name: "malformed part header in nested multipart",
			body: "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
				"--b\r\nContent-Type: multipart/alternative; boundary=c\r\n\r\n" +
				"--c\r\nBad header line\r\n\r\nx\r\n--c--\r\n" +
				"--b\r\nContent-Type: text/plain\r\n\r\nouter words\r\n" +
				"--b--\r\n",
			want:        "outer words",
			wantSkipped: true,
		},
		{
			name: "nested multipart without close delimiter",
			body: "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
				"--b\r\nContent-Type: multipart/alternative; boundary=c\r\n\r\n" +
				"--c\r\nContent-Type: text/html\r\n\r\n<p>x</p>\r\n" +
				"--b\r\nContent-Type: text/plain\r\n\r\nouter words\r\n" +
				"--b--\r\n",
			want:        "outer words",
			wantSkipped: true,
		},
		{
			name: "nested multipart without boundary parameter",
			body: "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
				"--b\r\nContent-Type: multipart/related\r\n\r\nbroken inner\r\n" +
				"--b\r\nContent-Type: text/plain\r\n\r\nouter words\r\n" +
				"--b--\r\n",
			want:        "outer words",
			wantSkipped: true,
		},
		{
			name: "outer html sibling after broken nested multipart",
			body: "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
				"--b\r\nContent-Type: multipart/alternative; boundary=c\r\n\r\n" +
				"--c\r\nBad header line\r\n\r\nx\r\n--c--\r\n" +
				"--b\r\nContent-Type: text/html\r\n\r\n<p>outer html words</p>\r\n" +
				"--b--\r\n",
			want:        "outer html words",
			wantSkipped: true,
		},
		{
			name: "attached text sibling skipped after broken nested multipart",
			body: "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
				"--b\r\nContent-Type: multipart/alternative; boundary=c\r\n\r\n" +
				"--c\r\nBad header line\r\n\r\nx\r\n--c--\r\n" +
				"--b\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=note.txt\r\n\r\nattached words\r\n" +
				"--b\r\nContent-Type: text/plain\r\nContent-Disposition: inline\r\n\r\ninline words\r\n" +
				"--b--\r\n",
			want:        "inline words",
			wantSkipped: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := rfcHeader + tt.body
			entity, err := message.Read(strings.NewReader(raw))
			if err != nil {
				t.Fatalf("message.Read: %v", err)
			}

			text, extractErr := ExtractPlaintextBody(entity)
			got := strings.TrimSpace(deref(text))
			if tt.want == "" {
				if text != nil {
					t.Errorf("ExtractPlaintextBody = %q (err %v), want <nil>", *text, extractErr)
				}
			} else if text == nil || got != tt.want {
				t.Errorf("ExtractPlaintextBody = %q (err %v), want %q", deref(text), extractErr, tt.want)
			}
			if (extractErr != nil) != tt.wantSkipped {
				t.Errorf("ExtractPlaintextBody err = %v, want skipped error: %v", extractErr, tt.wantSkipped)
			}

			if preview := MessagePreview(strings.NewReader(raw)); preview != tt.want {
				t.Errorf("MessagePreview = %q, want %q", preview, tt.want)
			}
		})
	}
}

func TestExtractPlaintextBody_BoundsDeepMultipartNesting(t *testing.T) {
	var b strings.Builder
	b.WriteString("From: a@example.com\r\nTo: b@example.com\r\nSubject: deep\r\nMIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=outer\r\n\r\n")
	b.WriteString("--outer\r\n")
	const depth = 64
	for i := 0; i < depth; i++ {
		fmt.Fprintf(&b, "Content-Type: multipart/mixed; boundary=nest-%d\r\n\r\n--nest-%d\r\n", i, i)
	}
	b.WriteString("Content-Type: text/plain\r\n\r\ntoo deep\r\n")
	for i := depth - 1; i >= 0; i-- {
		fmt.Fprintf(&b, "--nest-%d--\r\n", i)
	}
	b.WriteString("--outer\r\nContent-Type: text/plain\r\n\r\nshallow outer words\r\n--outer--\r\n")

	raw := b.String()
	entity, err := message.Read(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("message.Read: %v", err)
	}
	text, extractErr := ExtractPlaintextBody(entity)
	if extractErr != nil || text == nil || strings.TrimSpace(*text) != "shallow outer words" {
		t.Errorf("ExtractPlaintextBody = %q (err %v), want \"shallow outer words\"", deref(text), extractErr)
	}
	if preview := MessagePreview(strings.NewReader(raw)); preview != "shallow outer words" {
		t.Errorf("MessagePreview = %q, want \"shallow outer words\"", preview)
	}
}
