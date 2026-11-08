package helpers

import (
	"fmt"
	"strings"
	"testing"
)

func TestAttachmentKeyword_MIMEStructure(t *testing.T) {
	for _, tc := range []struct {
		name  string
		data  string
		valid bool
	}{
		{"plain", "Subject: plain\r\n\r\nbody", true},
		{"opaque body", "Content-Type: application/octet-stream\r\n\r\n\x00\xff", true},
		{"multipart", "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nbody\r\n--b--\r\n", true},
		{"closing boundary without newline", "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nbody\r\n--b--", true},
		{"bad header", "not a header\r\n\r\nbody", false},
		{"bad media parameters", "Content-Type: multipart/mixed; boundary=\"unclosed\r\n\r\nbody", false},
		{"missing media subtype", "Content-Type: multipart\r\n\r\nbody", false},
		{"bad disposition parameters", "Content-Disposition: inline; filename=\"unclosed\r\n\r\nbody", false},
		{"no boundary parameter", "Content-Type: multipart/mixed\r\n\r\nbody", false},
		{"boundary never matches", "Content-Type: multipart/mixed; boundary=b\r\n\r\nbody", false},
		{"empty multipart", "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b--\r\n", false},
		{"missing closing boundary", "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nbody", false},
		{"bad part header", "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nnot a header\r\n\r\nbody\r\n--b--\r\n", false},
		{"malformed second part after plaintext", "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nplain\r\n--b\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\nmissing inner boundary\r\n--b--\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if kw, known := AttachmentKeyword([]byte(tc.data)); known != tc.valid || (known && kw != KeywordHasNoAttachment) {
				t.Fatalf("AttachmentKeyword = %q, %v; want known-no-attachments=%v", kw, known, tc.valid)
			}
		})
	}
}

func TestAttachmentKeyword_MIMEStructure_NestedParts(t *testing.T) {
	var data strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&data, "Content-Type: multipart/mixed; boundary=b%d\r\n\r\n--b%d\r\n", i, i)
	}
	data.WriteString("Content-Type: text/plain\r\n\r\nbody")
	for i := 99; i >= 0; i-- {
		fmt.Fprintf(&data, "\r\n--b%d--\r\n", i)
	}
	if kw, known := AttachmentKeyword([]byte(data.String())); !known || kw != KeywordHasNoAttachment {
		t.Fatalf("AttachmentKeyword = %q, %v; want no attachments", kw, known)
	}
}
