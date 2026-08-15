package imap

import (
	"bytes"
	"errors"
	"io"
	"testing"

	serverPkg "github.com/migadu/sora/server"
)

// slowLiteralReader mimics an APPEND literal arriving from a slow client: it hands out
// the payload in small pieces and reports what the session memory tracker saw while the
// bytes were in flight.
type slowLiteralReader struct {
	data      []byte
	pos       int
	pieceSize int
	tracker   *serverPkg.SessionMemoryTracker
	observed  []int64 // tracker.Current() at each Read
	reads     int
}

func (r *slowLiteralReader) Size() int64 { return int64(len(r.data)) }

func (r *slowLiteralReader) Read(p []byte) (int, error) {
	r.reads++
	if r.tracker != nil {
		r.observed = append(r.observed, r.tracker.Current())
	}
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := r.pieceSize
	if n > len(p) {
		n = len(p)
	}
	if r.pos+n > len(r.data) {
		n = len(r.data) - r.pos
	}
	copy(p, r.data[r.pos:r.pos+n])
	r.pos += n
	return n, nil
}

// TestAppend_LiteralIsChargedWhileItIsRead covers APPEND-1: the literal is resident for
// the whole network read, so the session memory budget must see it for that whole
// window — not after the fact, and not never.
func TestAppend_LiteralIsChargedWhileItIsRead(t *testing.T) {
	payload := bytes.Repeat([]byte("m"), 512*1024)
	tracker := serverPkg.NewSessionMemoryTracker(0)
	s := &IMAPSession{server: &IMAPServer{}, memTracker: tracker}
	r := &slowLiteralReader{data: payload, pieceSize: 8 * 1024, tracker: tracker}

	data, release, err := s.readAppendLiteral(r)
	if err != nil {
		t.Fatalf("readAppendLiteral: %v", err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("read %d bytes, want %d", len(data), len(payload))
	}
	if r.reads < 2 {
		t.Fatalf("fixture did not exercise a multi-read literal (%d reads)", r.reads)
	}

	for i, seen := range r.observed {
		if seen < int64(len(payload)) {
			t.Fatalf("memory tracker at read %d = %d bytes, want the full literal (%d) reserved for the whole read window",
				i, seen, len(payload))
		}
	}
	if got, want := tracker.Current(), int64(len(payload)); got != want {
		t.Errorf("memory tracker after the read = %d bytes, want %d", got, want)
	}

	release()
	if got := tracker.Current(); got != 0 {
		t.Errorf("memory tracker after release = %d bytes, want 0", got)
	}
}

// TestAppend_LiteralOverBudgetIsRefusedBeforeReading checks that the budget actually
// bites: an oversized literal must be refused before it is pulled into memory.
func TestAppend_LiteralOverBudgetIsRefusedBeforeReading(t *testing.T) {
	payload := bytes.Repeat([]byte("m"), 64*1024)
	tracker := serverPkg.NewSessionMemoryTracker(32 * 1024)
	s := &IMAPSession{server: &IMAPServer{}, memTracker: tracker}
	r := &slowLiteralReader{data: payload, pieceSize: 4096, tracker: tracker}

	data, release, err := s.readAppendLiteral(r)
	defer release()
	if !errors.Is(err, errAppendLiteralTooLarge) {
		t.Fatalf("error = %v, want %v", err, errAppendLiteralTooLarge)
	}
	if len(data) != 0 {
		t.Errorf("read %d bytes of a refused literal, want 0", len(data))
	}
	if r.reads != 0 {
		t.Errorf("refused literal was read %d times, want 0", r.reads)
	}
	if got := tracker.Current(); got != 0 {
		t.Errorf("memory tracker after refusal = %d bytes, want 0", got)
	}
}

// TestAppend_RetainedBodySectionDoesNotBlockAnAppend covers the interaction between the
// two budgets: bytes retained only to make the next FETCH chunk cheaper are given back
// rather than costing the session an APPEND it could otherwise take.
func TestAppend_RetainedBodySectionDoesNotBlockAnAppend(t *testing.T) {
	payload := bytes.Repeat([]byte("m"), 32*1024)
	tracker := serverPkg.NewSessionMemoryTracker(int64(len(payload)))
	s := &IMAPSession{server: &IMAPServer{}, memTracker: tracker}

	retained := bytes.Repeat([]byte("r"), 8*1024)
	if !s.retainBodySection("retained", retained) {
		t.Fatal("section not retained")
	}
	if err := tracker.Allocate(int64(len(retained))); err != nil {
		t.Fatal(err)
	}

	r := &slowLiteralReader{data: payload, pieceSize: 4096, tracker: tracker}
	data, release, err := s.readAppendLiteral(r)
	defer release()
	if err != nil {
		t.Fatalf("readAppendLiteral: %v", err)
	}
	if len(data) != len(payload) {
		t.Fatalf("read %d bytes, want %d", len(data), len(payload))
	}
	if got := s.cachedBodySection("retained"); got != nil {
		t.Error("retained section survived a fetch that needed its budget")
	}
}

// TestAppend_ShortLiteralSettlesTheReservation covers a client that declares more than
// it sends: the reservation must shrink to what actually arrived.
func TestAppend_ShortLiteralSettlesTheReservation(t *testing.T) {
	tracker := serverPkg.NewSessionMemoryTracker(0)
	s := &IMAPSession{server: &IMAPServer{}, memTracker: tracker}
	r := &shortLiteralReader{declared: 1024, data: bytes.Repeat([]byte("m"), 100)}

	data, release, err := s.readAppendLiteral(r)
	if err != nil {
		t.Fatalf("readAppendLiteral: %v", err)
	}
	if len(data) != 100 {
		t.Fatalf("read %d bytes, want 100", len(data))
	}
	if got, want := tracker.Current(), int64(100); got != want {
		t.Errorf("memory tracker = %d bytes, want %d", got, want)
	}
	release()
	if got := tracker.Current(); got != 0 {
		t.Errorf("memory tracker after release = %d bytes, want 0", got)
	}
}

type shortLiteralReader struct {
	declared int64
	data     []byte
	pos      int
}

func (r *shortLiteralReader) Size() int64 { return r.declared }

func (r *shortLiteralReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
