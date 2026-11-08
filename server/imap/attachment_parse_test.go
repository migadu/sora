package imap

import (
	"testing"

	"github.com/migadu/sora/helpers"
)

func TestExtractBodyStructureSafe_MalformedMultipart(t *testing.T) {
	raw := []byte("Content-Type: multipart/mixed; boundary=declared\r\n\r\n" +
		"--actual\r\nContent-Type: text/plain\r\n\r\nbody\r\n--actual--\r\n")
	bs := extractBodyStructureSafe(raw)
	if bs == nil {
		t.Fatal("malformed mail still needs a serializable body structure")
	}
	if _, known := helpers.AttachmentKeyword(raw); known {
		t.Fatal("the extractor's synthetic multipart child must not count as a successful MIME parse")
	}
}
