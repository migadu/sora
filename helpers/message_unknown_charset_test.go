package helpers

import (
	"strings"
	"testing"

	"github.com/emersion/go-message"
)

// go-message reports an unknown charset or transfer encoding per MIME part, and
// the multipart reader can go on to the next part. FTS text must keep the rest
// of the message, as PREVIEW does (#1809).
func TestExtractPlaintextBody_UnknownCodingInMultipart(t *testing.T) {
	const head = "From: a@example.com\r\nTo: b@example.com\r\nSubject: probe\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=b1\r\n\r\n"
	const plainPart = "--b1\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nplain words\r\n"

	tests := []struct {
		name        string
		parts       string
		want        string
		wantSkipped bool // the part with the unknown coding is reported as skipped
	}{
		{
			name:  "unknown charset",
			parts: "--b1\r\nContent-Type: text/plain; charset=x-no-such-charset\r\n\r\nhello words\r\n",
			want:  "hello words",
		},
		{
			name: "unknown charset keeps its transfer decoding",
			parts: "--b1\r\nContent-Type: text/plain; charset=x-no-such-charset\r\n" +
				"Content-Transfer-Encoding: quoted-printable\r\n\r\nhello=20words\r\n",
			want: "hello words",
		},
		{
			name:  "part after an unknown charset",
			parts: "--b1\r\nContent-Type: text/html; charset=x-no-such-charset\r\n\r\n<p>html words</p>\r\n" + plainPart,
			want:  "plain words",
		},
		{
			name: "part after an unknown transfer encoding",
			parts: "--b1\r\nContent-Type: text/plain; charset=utf-8\r\n" +
				"Content-Transfer-Encoding: x-no-such-encoding\r\n\r\nencoded words\r\n" + plainPart,
			want:        "plain words",
			wantSkipped: true,
		},
		{
			// go-message reports only the charset then, and leaves the body encoded.
			name: "unknown charset and transfer encoding",
			parts: "--b1\r\nContent-Type: text/plain; charset=x-no-such-charset\r\n" +
				"Content-Transfer-Encoding: x-no-such-encoding\r\n\r\nencoded words\r\n" + plainPart,
			want:        "plain words",
			wantSkipped: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := head + tt.parts + "--b1--\r\n"
			entity, err := message.Read(strings.NewReader(raw))
			if err != nil {
				t.Fatalf("message.Read: %v", err)
			}

			text, err := ExtractPlaintextBody(entity)
			if text == nil || strings.TrimSpace(*text) != tt.want {
				t.Errorf("ExtractPlaintextBody = %q (err %v), want %q", deref(text), err, tt.want)
			}
			if tt.wantSkipped != (err != nil) {
				t.Errorf("ExtractPlaintextBody err = %v, want a skipped part reported: %v", err, tt.wantSkipped)
			}

			if got := MessagePreview(strings.NewReader(raw)); got != tt.want {
				t.Errorf("MessagePreview = %q, want %q", got, tt.want)
			}
		})
	}
}
