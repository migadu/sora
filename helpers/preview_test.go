package helpers

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func previewMessage(header, body string) string {
	return strings.ReplaceAll(header, "\n", "\r\n") + "\r\n" + strings.ReplaceAll(body, "\n", "\r\n")
}

func TestMessagePreview(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  string
		want string
	}{
		{
			name: "plain",
			msg:  previewMessage("Subject: hi\nContent-Type: text/plain\n", "Lunch   at\n\n noon?\n"),
			want: "Lunch at noon?",
		},
		{
			name: "no content type",
			msg:  previewMessage("Subject: hi\n", "Plain by default.\n"),
			want: "Plain by default.",
		},
		{
			name: "html only",
			msg: previewMessage("Content-Type: text/html\n",
				"<html><head><title>T</title><style>p { color: red }</style></head>"+
					"<body><p>Hello <b>there</b></p><script>alert(1)</script></body></html>"),
			want: "Hello there",
		},
		{
			name: "alternative with a blank plain part",
			msg: previewMessage("Content-Type: multipart/alternative; boundary=b\n",
				"--b\nContent-Type: text/plain\n\n \n\n--b\nContent-Type: text/html\n\n<p>From HTML</p>\n--b--\n"),
			want: "From HTML",
		},
		{
			name: "alternative prefers plain",
			msg: previewMessage("Content-Type: multipart/alternative; boundary=b\n",
				"--b\nContent-Type: text/plain\n\nFrom plain\n--b\nContent-Type: text/html\n\n<p>From HTML</p>\n--b--\n"),
			want: "From plain",
		},
		{
			name: "quoted-printable",
			msg:  previewMessage("Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n", "Caf=C3=A9 au l=\nait\n"),
			want: "Café au lait",
		},
		{
			name: "base64",
			msg:  previewMessage("Content-Type: text/plain\nContent-Transfer-Encoding: base64\n", "SGVsbG8gYmFzZTY0\n"),
			want: "Hello base64",
		},
		{
			name: "iso-8859-1",
			msg:  previewMessage("Content-Type: text/plain; charset=iso-8859-1\nContent-Transfer-Encoding: quoted-printable\n", "Gr=FC=DFe\n"),
			want: "Grüße",
		},
		{
			name: "text attachment is skipped",
			msg: previewMessage("Content-Type: multipart/mixed; boundary=b\n",
				"--b\nContent-Type: text/plain\nContent-Disposition: attachment; filename=notes.txt\n\nSecret notes\n"+
					"--b\nContent-Type: text/plain\n\nThe body\n--b--\n"),
			want: "The body",
		},
		{
			name: "only an attachment",
			msg: previewMessage("Content-Type: multipart/mixed; boundary=b\n",
				"--b\nContent-Type: application/pdf\nContent-Disposition: attachment; filename=a.pdf\n\n%PDF-1.4\n--b--\n"),
			want: "",
		},
		{
			name: "inline PGP message",
			msg:  previewMessage("Content-Type: text/plain\n", "\n-----BEGIN PGP MESSAGE-----\n\nhQEMA...\n-----END PGP MESSAGE-----\n"),
			want: "",
		},
		{
			name: "PGP/MIME",
			msg: previewMessage(`Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=b`+"\n",
				"--b\nContent-Type: application/pgp-encrypted\n\nVersion: 1\n--b\nContent-Type: application/octet-stream\n\n-----BEGIN PGP MESSAGE-----\n...\n--b--\n"),
			want: "",
		},
		{
			name: "S/MIME",
			msg:  previewMessage("Content-Type: application/pkcs7-mime; smime-type=enveloped-data\nContent-Transfer-Encoding: base64\n", "MIAGCSqGSIb3DQEHA6CAMIACAQAx\n"),
			want: "",
		},
		{
			name: "PGP clearsigned",
			msg: previewMessage("Content-Type: text/plain\n",
				"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nSigned text here.\n-----BEGIN PGP SIGNATURE-----\n\niQEz...\n-----END PGP SIGNATURE-----\n"),
			want: "Signed text here.",
		},
		{
			name: "quote and signature",
			msg: previewMessage("Content-Type: text/plain\n",
				"Sounds good.\n\n> Shall we meet?\n> Bob\n\n-- \nAlice\nExample Corp\n"),
			want: "Sounds good.",
		},
		{
			name: "only a quote",
			msg:  previewMessage("Content-Type: text/plain\n", "> forwarded line\n"),
			want: "forwarded line",
		},
		{
			name: "control and bidi characters",
			msg:  previewMessage("Content-Type: text/plain; charset=utf-8\n", "a\tb\x00c‮dcba‬ ​z‍w\n"),
			want: "a b cdcba z‍w",
		},
		{
			name: "malformed multipart",
			msg:  previewMessage("Content-Type: multipart/mixed; boundary=b\n", "--b\nContent-Type: text/plain\n\nBefore the break\n--b\nContent-Type: text/plain; charset=\"\n"),
			want: "Before the break",
		},
		{
			name: "not a message",
			msg:  "\x00\x01\x02",
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MessagePreview(strings.NewReader(tc.msg)); got != tc.want {
				t.Errorf("MessagePreview() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestMessagePreviewTruncation(t *testing.T) {
	t.Run("at a word boundary", func(t *testing.T) {
		body := strings.Repeat("word ", 100)
		got := MessagePreview(strings.NewReader(previewMessage("Content-Type: text/plain\n", body)))
		if n := utf8.RuneCountInString(got); n > PreviewMaxChars || n < PreviewMaxChars*3/4 {
			t.Errorf("len = %d characters, want at most %d", n, PreviewMaxChars)
		}
		if strings.HasSuffix(got, " ") || !strings.HasSuffix(got, "word") {
			t.Errorf("cut mid-word or with a trailing space: %q", got)
		}
	})
	t.Run("multibyte without spaces", func(t *testing.T) {
		body := strings.Repeat("日本語", 200)
		got := MessagePreview(strings.NewReader(previewMessage("Content-Type: text/plain; charset=utf-8\n", body)))
		if n := utf8.RuneCountInString(got); n != PreviewMaxChars {
			t.Errorf("len = %d characters, want %d", n, PreviewMaxChars)
		}
		if !utf8.ValidString(got) {
			t.Errorf("not valid UTF-8: %q", got)
		}
	})
}

// TestMessagePreviewBoundedInput checks that a huge part is read only as far
// as the preview needs, and that every source of the same bytes gives the same
// preview.
func TestMessagePreviewBoundedInput(t *testing.T) {
	huge := previewMessage("Content-Type: text/plain\n", "Start "+strings.Repeat("x", 20<<20))
	r := &countingReader{r: strings.NewReader(huge)}
	got := MessagePreview(r)
	if !strings.HasPrefix(got, "Start") {
		t.Errorf("MessagePreview() = %q, want it to start with the text", got)
	}
	if r.n > previewMaxInput+64<<10 {
		t.Errorf("read %d bytes of a %d-byte message, want at most about %d", r.n, len(huge), previewMaxInput)
	}
	if again := MessagePreview(bytes.NewReader([]byte(huge))); again != got {
		t.Errorf("preview differs between sources: %q vs %q", again, got)
	}
}

type countingReader struct {
	r interface{ Read([]byte) (int, error) }
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestMessagePreview_InvalidParametersWellFormedAlternativeWins(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  string
		want string
	}{
		{
			name: "well-formed html alternative wins over malformed plain",
			msg: previewMessage("Content-Type: multipart/alternative; boundary=b\n",
				"--b\nContent-Type: text/plain; charset=iso-8859-1; format\n\ncaf\xe9 words\n"+
					"--b\nContent-Type: text/html; charset=utf-8\n\n<p>café words</p>\n--b--\n"),
			want: "café words",
		},
		{
			name: "well-formed plain wins over earlier malformed plain",
			msg: previewMessage("Content-Type: multipart/alternative; boundary=b\n",
				"--b\nContent-Type: text/plain; charset=iso-8859-1; format\n\ncaf\xe9 words\n"+
					"--b\nContent-Type: text/plain; charset=utf-8\n\ncafé words\n--b--\n"),
			want: "café words",
		},
		{
			name: "well-formed html wins over earlier malformed html",
			msg: previewMessage("Content-Type: multipart/alternative; boundary=b\n",
				"--b\nContent-Type: text/html; charset=iso-8859-1; format\n\n<p>caf\xe9 words</p>\n"+
					"--b\nContent-Type: text/html; charset=utf-8\n\n<p>café words</p>\n--b--\n"),
			want: "café words",
		},
		{
			name: "well-formed html before malformed plain still wins",
			msg: previewMessage("Content-Type: multipart/alternative; boundary=b\n",
				"--b\nContent-Type: text/html; charset=utf-8\n\n<p>café words</p>\n"+
					"--b\nContent-Type: text/plain; charset=iso-8859-1; format\n\ncaf\xe9 words\n--b--\n"),
			want: "café words",
		},
		{
			name: "single-part malformed plain falls back",
			msg:  previewMessage("Content-Type: text/plain; charset=utf-8; format\n", "plain fallback\n"),
			want: "plain fallback",
		},
		{
			name: "single-part malformed html falls back",
			msg:  previewMessage("Content-Type: text/html; charset=utf-8; format\n", "<p>html fallback</p>\n"),
			want: "html fallback",
		},
		{
			name: "no well-formed alternative prefers malformed plain over malformed html",
			msg: previewMessage("Content-Type: multipart/alternative; boundary=b\n",
				"--b\nContent-Type: text/plain; charset=utf-8; format\n\nplain fallback\n"+
					"--b\nContent-Type: text/html; charset=utf-8; format\n\n<p>html fallback</p>\n--b--\n"),
			want: "plain fallback",
		},
		{
			name: "second malformed plain falls back after blank malformed plain",
			msg: previewMessage("Content-Type: multipart/mixed; boundary=b\n",
				"--b\nContent-Type: text/plain; charset=utf-8; format\n\n \n"+
					"--b\nContent-Type: text/plain; charset=utf-8; format\n\nsecond plain fallback\n--b--\n"),
			want: "second plain fallback",
		},
		{
			name: "blank well-formed html falls back to malformed plain",
			msg: previewMessage("Content-Type: multipart/alternative; boundary=b\n",
				"--b\nContent-Type: text/plain; charset=utf-8; format\n\nplain fallback\n"+
					"--b\nContent-Type: text/html; charset=utf-8\n\n<p>   </p>\n--b--\n"),
			want: "plain fallback",
		},
		{
			name: "blank well-formed plain falls back to malformed html",
			msg: previewMessage("Content-Type: multipart/alternative; boundary=b\n",
				"--b\nContent-Type: text/plain; charset=utf-8\n\n \n"+
					"--b\nContent-Type: text/html; charset=utf-8; format\n\n<p>html fallback</p>\n--b--\n"),
			want: "html fallback",
		},
		{
			name: "malformed plain PGP message returns empty",
			msg:  previewMessage("Content-Type: text/plain; charset=utf-8; format\n", "\n-----BEGIN PGP MESSAGE-----\n\nhQEMA...\n-----END PGP MESSAGE-----\n"),
			want: "",
		},
		{
			name: "malformed plain PGP message does not fall through to well-formed sibling",
			msg: previewMessage("Content-Type: multipart/mixed; boundary=b\n",
				"--b\nContent-Type: text/plain; charset=utf-8; format\n\n-----BEGIN PGP MESSAGE-----\n\nhQEMA...\n-----END PGP MESSAGE-----\n"+
					"--b\nContent-Type: text/html; charset=utf-8\n\n<p>Wrapper notice</p>\n--b--\n"),
			want: "",
		},
		{
			name: "malformed html PGP message returns empty",
			msg:  previewMessage("Content-Type: text/html; charset=utf-8; format\n", "<div>-----BEGIN PGP MESSAGE-----</div><div>hQEMA...</div><div>-----END PGP MESSAGE-----</div>\n"),
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := MessagePreview(strings.NewReader(tc.msg)); got != tc.want {
				t.Errorf("MessagePreview() = %q, want %q", got, tc.want)
			}
		})
	}
}
