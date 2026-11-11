package helpers

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/emersion/go-message/textproto"
)

func TestMessagePreviewHeaderLimits(t *testing.T) {
	t.Run("tiny header flood", func(t *testing.T) {
		// Under the 1 MiB raw cap, this used to allocate about 134 MB.
		msg := strings.Repeat("X:\r\n", (1<<20)/4-2) + "\r\nHi"
		r := &countingReader{r: strings.NewReader(msg)}
		if got := MessagePreview(r); got != "" {
			t.Fatalf("MessagePreview() = %q, want refusal of excessive header fields", got)
		}
		if r.n > previewMaxHeaderBytes {
			t.Fatalf("read %d bytes before refusing header flood, want early refusal", r.n)
		}
	})
	t.Run("oversized folded header", func(t *testing.T) {
		msg := "X: value\r\n" + strings.Repeat(" continued\r\n", 7000) + "\r\nHi"
		if got := MessagePreview(strings.NewReader(msg)); got != "" {
			t.Fatalf("MessagePreview() = %q, want refusal of oversized headers", got)
		}
	})
	t.Run("field limit permits body", func(t *testing.T) {
		msg := strings.Repeat("X:\r\n", previewMaxHeaderFields) + "\r\nHello"
		if got := MessagePreview(strings.NewReader(msg)); got != "Hello" {
			t.Fatalf("MessagePreview() = %q, want Hello at field limit", got)
		}
	})
	t.Run("body lines are not counted as headers", func(t *testing.T) {
		msg := "Subject: hi\n\nHello\n" + strings.Repeat("X:\n", previewMaxHeaderFields*2)
		if got := MessagePreview(strings.NewReader(msg)); !strings.HasPrefix(got, "Hello") {
			t.Fatalf("MessagePreview() = %q, want body text", got)
		}
	})
	t.Run("child header budget", func(t *testing.T) {
		msg := "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n" +
			strings.Repeat("X:\r\n", (1<<20)/4-100) + "\r\nHi\r\n--b--\r\n"
		if got := MessagePreview(strings.NewReader(msg)); got != "" {
			t.Fatalf("MessagePreview() = %q, want refusal of excessive child headers", got)
		}
	})
}

func TestPreviewHeaderReaderAcrossChunks(t *testing.T) {
	for _, newline := range []string{"\r\n", "\n"} {
		input := "Subject: hi" + newline + " continuation" + newline + newline + strings.Repeat("X:"+newline, previewMaxHeaderFields*2)
		r := &previewHeaderReader{r: &oneBytePreviewReader{s: input}, inHeader: true}
		got, err := io.ReadAll(r)
		if err != nil || string(got) != input {
			t.Fatalf("newline %q: read %d bytes, error %v", newline, len(got), err)
		}
		if r.headerFields != 1 || r.inHeader {
			t.Fatalf("newline %q: header reader did not stop at blank line: %+v", newline, r)
		}
	}
	r := &previewHeaderReader{r: &oneBytePreviewReader{s: strings.Repeat("X:\r\n", previewMaxHeaderFields+1)}, inHeader: true}
	if _, err := io.ReadAll(r); !errors.Is(err, textproto.ErrHeaderTooBig) {
		t.Fatalf("field limit error = %v, want ErrHeaderTooBig", err)
	}
}

type oneBytePreviewReader struct{ s string }

func (r *oneBytePreviewReader) Read(p []byte) (int, error) {
	if len(r.s) == 0 {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	p[0], r.s = r.s[0], r.s[1:]
	return 1, nil
}
