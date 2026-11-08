package helpers

import "testing"

// RFC 2183 §2.8 gives unknown disposition types attachment semantics. RFC 2045
// §5.1 permits comments in Content-Type; they do not change the media type.
func TestAttachmentKeyword_RFCDispositionAndMediaTypes(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      string
	}{
		{"unknown disposition", "Content-Type: text/plain\r\nContent-Disposition: x-custom\r\n\r\nbody", "$hasattachment"},
		{"unknown disposition with empty filename", "Content-Type: text/plain\r\nContent-Disposition: X-Custom; filename=\"\"\r\n\r\nbody", "$hasattachment"},
		{"inline control", "Content-Type: text/plain\r\nContent-Disposition: inline\r\n\r\nbody", "$hasnoattachment"},
		{"commented signature media type", "Content-Type: application/pkcs7-signature (S/MIME)\r\nContent-Disposition: attachment\r\n\r\nsignature", "$hasnoattachment"},
		{"commented PGP signature media type", "Content-Type: application/pgp-signature (signature)\r\nContent-Disposition: attachment\r\n\r\nsignature", "$hasnoattachment"},
		{"commented encrypted media type", "Content-Type: application/pkcs7-mime (encrypted)\r\nContent-Disposition: attachment\r\n\r\nciphertext", ""},
		{"comment between media tokens", "Content-Type: application/(signed)pkcs7-signature\r\nContent-Disposition: attachment\r\n\r\nsignature", "$hasnoattachment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyword, known := AttachmentKeyword([]byte(tc.raw))
			if string(keyword) != tc.want || known != (tc.want != "") {
				t.Fatalf("AttachmentKeyword = %q, %v; want %q", keyword, known, tc.want)
			}
		})
	}
}

// The message/rfc822 default in RFC 2046 §5.1.5 belongs to immediate children
// of multipart/digest. It does not replace the top-level default or leak into
// children of a nested explicit multipart/mixed entity.
func TestAttachmentKeyword_RFCDigestDefaultScope(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"top level defaults to plain", "From: sender@example.com\r\nSubject: plain message\r\n\r\nbody"},
		{"explicit plain digest child", "Content-Type: multipart/digest; boundary=d\r\n\r\n--d\r\nContent-Type: text/plain\r\n\r\nbody\r\n--d--\r\n"},
		{"mixed inside digest resets child default", "Content-Type: multipart/digest; boundary=d\r\n\r\n--d\r\nContent-Type: multipart/mixed; boundary=m\r\n\r\n--m\r\n\r\nFrom: sender@example.com\r\n\r\nbody\r\n--m--\r\n--d--\r\n"},
		{"following mixed sibling uses plain default", "Content-Type: multipart/mixed; boundary=m\r\n\r\n--m\r\nContent-Type: multipart/digest; boundary=d\r\n\r\n--d\r\nContent-Type: text/plain\r\n\r\nbody\r\n--d--\r\n--m\r\n\r\nFrom: sender@example.com\r\n\r\nbody\r\n--m--\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyword, known := AttachmentKeyword([]byte(tc.raw))
			if !known || keyword != KeywordHasNoAttachment {
				t.Fatalf("AttachmentKeyword = %q, %v; want no attachments", keyword, known)
			}
		})
	}
}

func TestAttachmentKeyword_AmbiguousMIMEHeaders(t *testing.T) {
	for _, raw := range []string{
		"Content-Type: text/plain\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Disposition: attachment\r\n\r\nPDF\r\n--b--\r\n",
		"Content-Type: application/pdf\r\nContent-Disposition: inline\r\nContent-Disposition: attachment\r\n\r\nPDF",
	} {
		keyword, known := AttachmentKeyword([]byte(raw))
		if known {
			t.Fatalf("ambiguous MIME headers yielded %q; want unknown", keyword)
		}
	}
	// Conflicting disposition fields do not make a unique MIME boundary
	// ambiguous, so a real child attachment still settles the positive result.
	raw := "Content-Type: multipart/mixed; boundary=b\r\nContent-Disposition: inline\r\nContent-Disposition: x-custom\r\n\r\n" +
		"--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment\r\n\r\nPDF\r\n--b--\r\n"
	if keyword, known := AttachmentKeyword([]byte(raw)); !known || keyword != KeywordHasAttachment {
		t.Fatalf("definite child attachment yielded %q, %v", keyword, known)
	}
}
