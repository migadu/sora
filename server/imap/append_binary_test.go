package imap

import (
	"bytes"
	"errors"
	"testing"

	serverPkg "github.com/migadu/sora/server"
)

func TestAppendBinaryNormalizationMemory(t *testing.T) {
	raw := append([]byte("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n"), bytes.Repeat([]byte{0, 0xff, '\n'}, 100)...)
	t.Run("original and encoded buffers are both charged", func(t *testing.T) {
		tracker := serverPkg.NewSessionMemoryTracker(4096)
		s := &IMAPSession{server: &IMAPServer{}, memTracker: tracker}
		if err := tracker.Allocate(int64(len(raw))); err != nil {
			t.Fatal(err)
		}
		data, release, err := s.normalizeBinaryAppend(raw)
		defer release()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.IndexByte(data, 0) >= 0 {
			t.Fatal("normalized message still contains NUL")
		}
		if got, want := tracker.Current(), int64(len(raw)+len(data)); got != want {
			t.Fatalf("charged %d bytes, want original and encoded buffers: %d", got, want)
		}
		release()
		if got := tracker.Current(); got != int64(len(raw)) {
			t.Fatalf("normalization release left %d bytes, want original literal %d", got, len(raw))
		}
		release()
		if got := tracker.Current(); got != int64(len(raw)) {
			t.Fatalf("repeated release charged %d bytes, want original literal %d", got, len(raw))
		}
	})
	t.Run("encoded buffer must fit beside original", func(t *testing.T) {
		tracker := serverPkg.NewSessionMemoryTracker(int64(len(raw) + 1))
		s := &IMAPSession{server: &IMAPServer{}, memTracker: tracker}
		if err := tracker.Allocate(int64(len(raw))); err != nil {
			t.Fatal(err)
		}
		data, release, err := s.normalizeBinaryAppend(raw)
		defer release()
		if !errors.Is(err, errAppendLiteralTooLarge) {
			t.Fatalf("error = %v, want memory-budget refusal", err)
		}
		if len(data) != 0 {
			t.Fatal("refused normalization returned a message")
		}
		if got := tracker.Current(); got != int64(len(raw)) {
			t.Fatalf("refusal changed literal reservation to %d bytes", got)
		}
	})
	t.Run("already encoded message uses original reservation", func(t *testing.T) {
		safe := []byte("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\nAP8=\r\n")
		tracker := serverPkg.NewSessionMemoryTracker(int64(len(safe)))
		s := &IMAPSession{server: &IMAPServer{}, memTracker: tracker}
		if err := tracker.Allocate(int64(len(safe))); err != nil {
			t.Fatal(err)
		}
		data, release, err := s.normalizeBinaryAppend(safe)
		defer release()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, safe) || &data[0] != &safe[0] {
			t.Fatal("safe message was copied or changed")
		}
		if got := tracker.Current(); got != int64(len(safe)) {
			t.Fatalf("safe message needs an extra %d-byte reservation", got-int64(len(safe)))
		}
	})
}
