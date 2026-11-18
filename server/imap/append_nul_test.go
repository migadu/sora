package imap

import (
	"bytes"
	"errors"
	"testing"

	serverPkg "github.com/migadu/sora/server"
)

// The NUL-part encoding of a non-BINARY APPEND follows the same budget rule as
// the literal8 normalization: the whole encoded copy is reserved, beside the
// literal, before it is allocated, and a refused reservation fails the APPEND.
func TestAppendNULEncodingMemory(t *testing.T) {
	raw := append([]byte("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n"), bytes.Repeat([]byte{0, 0xff, '\n'}, 100)...)
	session := func(budget int64, literal []byte) (*IMAPSession, *serverPkg.SessionMemoryTracker) {
		t.Helper()
		tracker := serverPkg.NewSessionMemoryTracker(budget)
		if err := tracker.Allocate(int64(len(literal))); err != nil { // as readAppendLiteral does
			t.Fatal(err)
		}
		return &IMAPSession{server: &IMAPServer{}, memTracker: tracker}, tracker
	}

	t.Run("literal and encoded copy are both charged", func(t *testing.T) {
		s, tracker := session(4096, raw)
		data, release, err := s.encodeNULAppend(raw)
		defer release()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.IndexByte(data, 0) >= 0 {
			t.Fatal("encoded message still contains NUL")
		}
		if got, want := tracker.Current(), int64(len(raw)+len(data)); got != want {
			t.Fatalf("charged %d bytes, want literal and encoded copy: %d", got, want)
		}
		if got, want := tracker.Peak(), int64(len(raw)+len(data)); got != want {
			t.Fatalf("peak charge %d bytes, want literal and encoded copy at once: %d", got, want)
		}
		release()
		release()
		if got := tracker.Current(); got != int64(len(raw)) {
			t.Fatalf("release left %d bytes charged, want the literal's %d", got, len(raw))
		}
	})

	t.Run("encoded copy must fit beside the literal", func(t *testing.T) {
		// Room for the growth alone (what was charged before), not for the copy.
		s, tracker := session(int64(len(raw))*3/2, raw)
		data, release, err := s.encodeNULAppend(raw)
		defer release()
		if !errors.Is(err, errAppendLiteralTooLarge) {
			t.Fatalf("error = %v, want the memory-budget refusal", err)
		}
		if data != nil {
			t.Fatal("refused encoding returned a message")
		}
		if got := tracker.Current(); got != int64(len(raw)) {
			t.Fatalf("refusal left %d bytes charged, want the literal's %d", got, len(raw))
		}
	})

	t.Run("message without NUL is neither copied nor charged", func(t *testing.T) {
		safe := []byte("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n\x01\xff\r\n")
		s, tracker := session(int64(len(safe)), safe)
		data, release, err := s.encodeNULAppend(safe)
		defer release()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, safe) || &data[0] != &safe[0] {
			t.Fatal("message without NUL was copied or changed")
		}
		if got := tracker.Current(); got != int64(len(safe)) {
			t.Fatalf("message without NUL charged an extra %d bytes", got-int64(len(safe)))
		}
	})
}
