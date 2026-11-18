package imap

import (
	"bytes"
	"io"
	"strings"
	"testing"

	imap "github.com/migadu/go-imap"
)

type captureSectionWriter struct {
	size int64
	buf  bytes.Buffer
}

type nopCloseWriter struct{ io.Writer }

func (nopCloseWriter) Close() error { return nil }

func (c *captureSectionWriter) WriteBodySection(_ *imap.FetchItemBodySection, size int64) io.WriteCloser {
	c.size = size
	return nopCloseWriter{&c.buf}
}

// writeBodySectionData sends each NUL of a BODY section as 0x80 (#2073), keeps
// the size, and leaves the section it was given as it is: that can be the
// message body or a section retained for later chunks.
func TestWriteBodySectionDataReplacesNUL(t *testing.T) {
	section := &imap.FetchItemBodySection{Part: []int{1}}
	for _, tc := range []struct {
		name, content, want string
		nuls                int
	}{
		{"no NUL", "abc\r\n\x01\xff", "abc\r\n\x01\xff", 0},
		{"NULs", "\x00a\x00\x00b\x00", "\x80a\x80\x80b\x80", 4},
		{"longer than the copy buffer", strings.Repeat("x\x00", 40<<10), strings.Repeat("x\x80", 40<<10), 40 << 10},
		{"empty", "", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			content := []byte(tc.content)
			var w captureSectionWriter
			nuls, err := writeBodySectionData(&w, section, content)
			if err != nil {
				t.Fatal(err)
			}
			if w.buf.String() != tc.want || nuls != tc.nuls {
				t.Fatalf("sent %q (%d NULs), want %q (%d)", w.buf.Bytes(), nuls, tc.want, tc.nuls)
			}
			if w.size != int64(len(tc.content)) {
				t.Fatalf("literal size %d, want %d", w.size, len(tc.content))
			}
			if string(content) != tc.content {
				t.Fatal("the section it was given was modified")
			}
		})
	}
}
