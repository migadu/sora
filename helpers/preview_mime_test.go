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
