package helpers

import (
	"strings"
	"testing"

	"github.com/emersion/go-imap/v2"
)

// mime joins header and body lines with CRLF.
func mime(lines ...string) string {
	return strings.Join(lines, "\r\n") + "\r\n"
}

func TestAttachmentKeyword(t *testing.T) {
	const (
		has  = KeywordHasAttachment
		none = KeywordHasNoAttachment
		skip = imap.Flag("") // undecided: neither keyword
	)
	tests := []struct {
		name string
		msg  string
		want imap.Flag
	}{
		{"plain text", mime(
			"Content-Type: text/plain",
			"",
			"hello",
		), none},
		{"text and HTML alternatives", mime(
			`Content-Type: multipart/alternative; boundary="b"`,
			"",
			"--b",
			"Content-Type: text/plain",
			"",
			"hello",
			"--b",
			"Content-Type: text/html",
			"",
			"<p>hello</p>",
			"--b--",
		), none},
		{"PDF with disposition attachment", mime(
			`Content-Type: multipart/mixed; boundary="b"`,
			"",
			"--b",
			"Content-Type: text/plain",
			"",
			"see attached",
			"--b",
			"Content-Type: application/pdf",
			`Content-Disposition: attachment; filename="report.pdf"`,
			"",
			"JVBERi0=",
			"--b--",
		), has},
		{"Apple Mail inline PDF with a filename", mime(
			`Content-Type: multipart/mixed; boundary="b"`,
			"",
			"--b",
			"Content-Type: text/html",
			"",
			"<p>see attached</p>",
			"--b",
			`Content-Type: application/pdf; name="report.pdf"`,
			`Content-Disposition: inline; filename="report.pdf"`,
			"",
			"JVBERi0=",
			"--b--",
		), has},
		{"name-only attachment, no disposition", mime(
			`Content-Type: multipart/mixed; boundary="b"`,
			"",
			"--b",
			"Content-Type: text/plain",
			"",
			"see attached",
			"--b",
			`Content-Type: application/vnd.ms-excel; name="sheet.xls"`,
			"",
			"0M8R4KGx",
			"--b--",
		), has},
		{"RFC 2231 encoded filename", mime(
			`Content-Type: multipart/mixed; boundary="b"`,
			"",
			"--b",
			"Content-Type: text/plain",
			"",
			"x",
			"--b",
			"Content-Type: application/pdf",
			"Content-Disposition: inline; filename*=UTF-8''%E2%82%AC.pdf",
			"",
			"JVBERi0=",
			"--b--",
		), has},
		{"HTML with an embedded cid image", mime(
			`Content-Type: multipart/related; boundary="b"`,
			"",
			"--b",
			"Content-Type: text/html",
			"",
			`<img src="cid:logo">`,
			"--b",
			`Content-Type: image/png; name="logo.png"`,
			`Content-Disposition: inline; filename="logo.png"`,
			"Content-ID: <logo>",
			"",
			"iVBORw0=",
			"--b--",
		), none},
		{"attachment inside multipart/related still counts", mime(
			`Content-Type: multipart/related; boundary="b"`,
			"",
			"--b",
			"Content-Type: text/html",
			"",
			"<p>x</p>",
			"--b",
			"Content-Type: application/zip",
			`Content-Disposition: attachment; filename="files.zip"`,
			"",
			"UEsDBA==",
			"--b--",
		), has},
		{"attached multipart document", mime(
			`Content-Type: multipart/mixed; boundary="outer"`,
			"",
			"--outer", "Content-Type: text/plain", "", "See attached web page.",
			"--outer", `Content-Type: multipart/related; boundary="page"`,
			`Content-Disposition: attachment; filename="page.mhtml"`, "",
			"--page", "Content-Type: text/html", "", "<p>Attached page</p>",
			"--page--", "--outer--",
		), has},
		{"multipart document with a name only", mime(
			`Content-Type: multipart/mixed; boundary="b"; name="document.mime"`, "",
			"--b", "Content-Type: text/plain", "", "document body", "--b--",
		), has},
		{"named multipart resource inside related stays inline", mime(
			`Content-Type: multipart/related; boundary="outer"`, "",
			"--outer", `Content-Type: multipart/alternative; boundary="b"; name="body.mime"`, "",
			"--b", "Content-Type: text/plain", "", "body", "--b--", "--outer--",
		), none},
		{"forwarded message", mime(
			`Content-Type: multipart/mixed; boundary="b"`,
			"",
			"--b",
			"Content-Type: text/plain",
			"",
			"fyi",
			"--b",
			"Content-Type: message/rfc822",
			"",
			"Subject: original",
			"",
			"original body",
			"--b--",
		), has},
		{"S/MIME signature is not an attachment", mime(
			`Content-Type: multipart/signed; protocol="application/pkcs7-signature"; boundary="b"`,
			"",
			"--b",
			"Content-Type: text/plain",
			"",
			"signed",
			"--b",
			`Content-Type: application/pkcs7-signature; name="smime.p7s"`,
			`Content-Disposition: attachment; filename="smime.p7s"`,
			"",
			"MIAGCSqG",
			"--b--",
		), none},
		{"OpenPGP-signed mail with a real attachment", mime(
			`Content-Type: multipart/signed; protocol="application/pgp-signature"; boundary="s"`,
			"",
			"--s",
			`Content-Type: multipart/mixed; boundary="m"`,
			"",
			"--m",
			"Content-Type: text/plain",
			"",
			"signed",
			"--m",
			"Content-Type: application/pdf",
			`Content-Disposition: attachment; filename="a.pdf"`,
			"",
			"JVBERi0=",
			"--m--",
			"--s",
			`Content-Type: application/pgp-signature; name="signature.asc"`,
			"",
			"-----BEGIN PGP SIGNATURE-----",
			"--s--",
		), has},
		{"PGP/MIME encrypted is undecided", mime(
			`Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="b"`,
			"",
			"--b",
			"Content-Type: application/pgp-encrypted",
			"",
			"Version: 1",
			"--b",
			`Content-Type: application/octet-stream; name="encrypted.asc"`,
			"",
			"-----BEGIN PGP MESSAGE-----",
			"--b--",
		), skip},
		{"S/MIME encrypted is undecided", mime(
			`Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name="smime.p7m"`,
			`Content-Disposition: attachment; filename="smime.p7m"`,
			"",
			"MIAGCSqG",
		), skip},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := AttachmentKeyword([]byte(tt.msg))
			if tt.want == skip {
				if ok {
					t.Errorf("AttachmentKeyword = %q, want undecided", got)
				}
				return
			}
			if !ok || got != tt.want {
				t.Errorf("AttachmentKeyword = %q, %v; want %q", got, ok, tt.want)
			}
		})
	}
}

func TestAttachmentKeyword_Undecidable(t *testing.T) {
	if kw, ok := AttachmentKeyword(nil); ok {
		t.Errorf("AttachmentKeyword(nil) = %q, want undecided", kw)
	}
	// A multipart with no readable children says nothing about attachments.
	if kw, ok := AttachmentKeyword([]byte("Content-Type: multipart/mixed; boundary=b\r\n\r\n--b--\r\n")); ok {
		t.Errorf("AttachmentKeyword(empty multipart) = %q, want undecided", kw)
	}
}
