package helpers

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/emersion/go-message"
)

func TestHeaderPresenceKeepsEmptyInvalidAndGroupFields(t *testing.T) {
	for _, value := range []string{"", "undisclosed-recipients:;", "not an address", "A <a@example.org>"} {
		raw := "fRoM: " + value + "\r\nTo: " + value + "\r\nCc: " + value + "\r\n\r\nbody"
		e, err := message.Read(strings.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		for name, mask := range map[string]*int16{
			"parsed": ExtractHeaderPresence(e.Header),
			"raw":    ExtractRawHeaderPresence([]byte(raw)),
		} {
			for _, key := range []string{"from", "to", "cc"} {
				bit, _ := HeaderPresenceBit(key)
				if *mask&bit == 0 {
					t.Fatalf("%s lost %s=%q", name, key, value)
				}
			}
			bit, _ := HeaderPresenceBit("subject")
			if *mask&bit != 0 {
				t.Fatalf("%s invented Subject", name)
			}
		}
	}
}

func TestExtractRawHeaderPresenceMalformedAndEdgeCases(t *testing.T) {
	longVal := strings.Repeat("x", 10000) + "Cc: mid-line@example.com"
	raw := strings.Join([]string{
		" ContinuationOnFirstLine: ignored",
		"fRoM : sender@example.com",
		"MalformedLineWithoutColon",
		"Bad Space: ignored@example.com",
		"Messag\u0130-ID: <unicode-lookalike@example.com>",
		"Subject: " + longVal,
		"\tTo: folded-continuation@example.com",
		"ReFeReNcEs:",
		"",
		"To: in-body@example.com",
		"Bcc: in-body@example.com",
	}, "\r\n")

	mask := ExtractRawHeaderPresence([]byte(raw))
	if mask == nil {
		t.Fatal("expected non-nil mask")
	}
	wantSet := map[string]bool{
		"from":       true,
		"subject":    true,
		"references": true,
	}
	for _, key := range []string{"from", "to", "cc", "bcc", "sender", "reply-to", "subject", "message-id", "in-reply-to", "references"} {
		bit, _ := HeaderPresenceBit(key)
		got := (*mask & bit) != 0
		if got != wantSet[key] {
			t.Errorf("key %s: got %v, want %v", key, got, wantSet[key])
		}
	}

	// LF-only separator also stops before the body.
	lfMask := ExtractRawHeaderPresence([]byte("Cc: c@example.com\n\nTo: body@example.com\n"))
	ccBit, _ := HeaderPresenceBit("cc")
	toBit, _ := HeaderPresenceBit("to")
	if (*lfMask&ccBit) == 0 || (*lfMask&toBit) != 0 {
		t.Fatalf("LF separator failed: mask=%b", *lfMask)
	}
}

type failingAfterReader struct {
	data []byte
	err  error
}

func (f *failingAfterReader) Read(p []byte) (int, error) {
	if len(f.data) > 0 {
		n := copy(p, f.data)
		f.data = f.data[n:]
		return n, nil
	}
	return 0, f.err
}

func TestExtractRawHeaderPresenceFromReaderPropagatesMidHeaderError(t *testing.T) {
	boom := errors.New("connection reset")
	mask, err := ExtractRawHeaderPresenceFromReader(&failingAfterReader{
		data: []byte("From: a@example.com\r\n"),
		err:  boom,
	})
	if !errors.Is(err, boom) || mask != nil {
		t.Fatalf("got mask=%v err=%v, want nil and %v", mask, err, boom)
	}

	// Once the blank line is read, trailing body errors are never hit.
	mask, err = ExtractRawHeaderPresenceFromReader(&failingAfterReader{
		data: []byte("From: a@example.com\r\n\r\n"),
		err:  io.ErrUnexpectedEOF,
	})
	if err != nil || mask == nil {
		t.Fatalf("expected clean stop at blank line, got mask=%v err=%v", mask, err)
	}
	fromBit, _ := HeaderPresenceBit("from")
	if (*mask & fromBit) == 0 {
		t.Fatalf("expected from bit set, got %b", *mask)
	}
}
