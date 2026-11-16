package helpers

import (
	"strings"
	"testing"

	"github.com/emersion/go-message"
)

// A single-part message whose Content-Transfer-Encoding is unknown (RFC 2045 §6.4)
// must not have its undecoded body indexed as text: it must behave the same as the
// identical part inside a multipart, and agree with MessagePreview (#1816).
func TestExtractPlaintextBody_SinglePartUnknownTransferEncoding(t *testing.T) {
	const rfcHeader = "From: a@example.com\r\nTo: b@example.com\r\nSubject: probe\r\nMIME-Version: 1.0\r\n"

	tests := []struct {
		name        string
		partHeaders string
		body        string
		want        string
		wantSkipped bool
	}{
		{
			name:        "known quoted-printable control",
			partHeaders: "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n",
			body:        "hello=20words\r\n",
			want:        "hello words",
		},
		{
			name:        "unknown charset with known quoted-printable control",
			partHeaders: "Content-Type: text/plain; charset=x-no-such-charset\r\nContent-Transfer-Encoding: quoted-printable\r\n",
			body:        "hello=20words\r\n",
			want:        "hello words",
		},
		{
			name:        "base64 with RFC 822 comment control",
			partHeaders: "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64 (comment)\r\n",
			body:        "aGVsbG8gd29yZHMNCg==\r\n",
			want:        "hello words",
		},
		{
			name:        "unknown transfer encoding x-uuencode",
			partHeaders: "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: x-uuencode\r\n",
			body:        "begin 644 f\r\nM86)C\r\nend\r\n",
			wantSkipped: true,
		},
		{
			name:        "unknown transfer encoding on text/html",
			partHeaders: "Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: x-uuencode\r\n",
			body:        "begin 644 f\r\nM86)C\r\nend\r\n",
			wantSkipped: true,
		},
		{
			// go-message overwrites UnknownEncodingError with UnknownCharsetError here.
			name:        "unknown transfer encoding and unknown charset",
			partHeaders: "Content-Type: text/plain; charset=x-no-such-charset\r\nContent-Transfer-Encoding: x-uuencode\r\n",
			body:        "begin 644 f\r\nM86)C\r\nend\r\n",
			wantSkipped: true,
		},
		{
			name:        "malformed transfer encoding with trailing token",
			partHeaders: "Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit <center>\r\n",
			body:        "hello words\r\n",
			wantSkipped: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			singleRaw := rfcHeader + tt.partHeaders + "\r\n" + tt.body
			multiRaw := rfcHeader +
				"Content-Type: multipart/mixed; boundary=b1\r\n\r\n" +
				"--b1\r\n" + tt.partHeaders + "\r\n" + tt.body +
				"--b1--\r\n"

			singleEntity, err := message.Read(strings.NewReader(singleRaw))
			if err != nil && !message.IsUnknownCharset(err) && !message.IsUnknownEncoding(err) {
				t.Fatalf("single message.Read: %v", err)
			}
			multiEntity, err := message.Read(strings.NewReader(multiRaw))
			if err != nil && !message.IsUnknownCharset(err) && !message.IsUnknownEncoding(err) {
				t.Fatalf("multipart message.Read: %v", err)
			}

			singleText, singleErr := ExtractPlaintextBody(singleEntity)
			multiText, multiErr := ExtractPlaintextBody(multiEntity)

			gotSingle := strings.TrimSpace(deref(singleText))
			gotMulti := strings.TrimSpace(deref(multiText))

			if tt.want == "" {
				if singleText != nil {
					t.Errorf("single-part ExtractPlaintextBody = %q (err %v), want <nil>", *singleText, singleErr)
				}
				if multiText != nil {
					t.Errorf("multipart ExtractPlaintextBody = %q (err %v), want <nil>", *multiText, multiErr)
				}
			} else {
				if singleText == nil || gotSingle != tt.want {
					t.Errorf("single-part ExtractPlaintextBody = %q (err %v), want %q", deref(singleText), singleErr, tt.want)
				}
				if multiText == nil || gotMulti != tt.want {
					t.Errorf("multipart ExtractPlaintextBody = %q (err %v), want %q", deref(multiText), multiErr, tt.want)
				}
			}

			if (singleErr != nil) != tt.wantSkipped {
				t.Errorf("single-part err = %v, want skipped error: %v", singleErr, tt.wantSkipped)
			}
			if (multiErr != nil) != tt.wantSkipped {
				t.Errorf("multipart err = %v, want skipped error: %v", multiErr, tt.wantSkipped)
			}

			if got := MessagePreview(strings.NewReader(singleRaw)); got != tt.want {
				t.Errorf("single-part MessagePreview = %q, want %q", got, tt.want)
			}
			if got := MessagePreview(strings.NewReader(multiRaw)); got != tt.want {
				t.Errorf("multipart MessagePreview = %q, want %q", got, tt.want)
			}
		})
	}
}
