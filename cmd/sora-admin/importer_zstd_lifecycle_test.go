package main

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

// An abandoned stream still returns its decoder cleanly. In particular, a
// second Close must not return the same decoder to the pool twice.
func TestMaildirZstdCloseBeforeEOF(t *testing.T) {
	onDisk := mustDecodeHex(t, zstdMessageHex)
	for _, prefix := range []int64{0, 1, int64(len(dovecotMessage) - 1)} {
		t.Run(fmt.Sprintf("read_%d_bytes", prefix), func(t *testing.T) {
			reader, compressed, err := maildirContentReader(bytes.NewReader(onDisk))
			if err != nil || !compressed {
				t.Fatalf("maildirContentReader: compressed=%v, error=%v", compressed, err)
			}
			if _, err := io.CopyN(io.Discard, reader, prefix); err != nil {
				t.Fatal(err)
			}
			if err := reader.Close(); err != nil {
				t.Fatal(err)
			}
			if err := reader.Close(); err != nil {
				t.Fatalf("second Close: %v", err)
			}
			// Both streams remain open at once. Returning a decoder twice must
			// not let the first stream consume the second stream's input.
			streams := make([]io.ReadCloser, 2)
			for j := range streams {
				streams[j], _, err = maildirContentReader(bytes.NewReader(onDisk))
				if err != nil {
					t.Fatal(err)
				}
				defer streams[j].Close()
			}
			for j, stream := range streams {
				got, err := io.ReadAll(stream)
				if err != nil || string(got) != dovecotMessage {
					t.Fatalf("stream %d after abandoned stream: %d bytes, error=%v", j, len(got), err)
				}
			}
		})
	}
}
