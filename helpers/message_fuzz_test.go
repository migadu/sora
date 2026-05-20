package helpers

import (
	"bytes"
	"testing"

	"github.com/emersion/go-message"
)

func FuzzExtractPlaintextBody(f *testing.F) {
	// Add some seed corpora
	f.Add([]byte("From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nContent-Type: text/plain\r\n\r\nThis is a simple message body."))

	f.Add([]byte("From: sender@example.com\r\n" +
		"To: recipient@example.com\r\n" +
		"Subject: Multipart Test\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=\"boundary123\"\r\n" +
		"\r\n" +
		"--boundary123\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: 7bit\r\n" +
		"\r\n" +
		"First part is plain text.\r\n" +
		"--boundary123\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"\r\n" +
		"<html><body>Second part is HTML</body></html>\r\n" +
		"--boundary123--\r\n"))

	f.Add([]byte("From: sender@example.com\r\n" +
		"To: receiver@example.com\r\n" +
		"Subject: Nested Multipart\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"outer\"\r\n" +
		"\r\n" +
		"--outer\r\n" +
		"Content-Type: multipart/alternative; boundary=\"inner\"\r\n" +
		"\r\n" +
		"--inner\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\n" +
		"Inner plain\r\n" +
		"--inner--\r\n" +
		"--outer--\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Read using the go-message library (which is what we use in server.ParseMessage)
		// For unknown encodings/charsets, Read can return a degraded entity and a non-nil error.
		msg, err := message.Read(bytes.NewReader(data))
		if err != nil && msg == nil {
			return
		}
		if msg == nil {
			return
		}

		// Extract plaintext body
		_, _ = ExtractPlaintextBody(msg)
	})
}
