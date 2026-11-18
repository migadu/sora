package sieveengine

import (
	"bytes"
	"errors"
	"testing"
)

// ApplyHeaderEditsReserved gives the same bytes as ApplyHeaderEdits, and reserve
// is told exactly the size of the buffer it then allocates; a refusal returns
// the reserve error and no message.
func TestApplyHeaderEditsReserved(t *testing.T) {
	edits := []HeaderEdit{
		{Action: "add", FieldName: "X-First", Value: "1"},
		{Action: "add", FieldName: "X-Last", Value: "2", Last: true},
		{Action: "delete", FieldName: "X-Drop"},
	}
	for name, msg := range map[string]string{
		"crlf":             "From: a@example.com\r\nX-Drop: x\r\nSubject: s\r\n\r\nbody\r\n",
		"bare lf":          "From: a@example.com\nX-Drop: x\nSubject: s\n\nbody\n",
		"header only":      "From: a@example.com\r\nSubject: s",
		"folded and empty": "From: a@example.com\r\nX-Drop: x\r\n y\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			want, err := ApplyHeaderEdits([]byte(msg), edits)
			if err != nil {
				t.Fatal(err)
			}
			var reserved int64
			got, err := ApplyHeaderEditsReserved([]byte(msg), edits, func(size int64) error { reserved = size; return nil })
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("got %q, %v; want %q", got, err, want)
			}
			if reserved != int64(len(got)) || cap(got) != len(got) {
				t.Fatalf("reserved %d for %d bytes in a %d-byte buffer", reserved, len(got), cap(got))
			}
			refused := errors.New("over budget")
			if got, err := ApplyHeaderEditsReserved([]byte(msg), edits, func(int64) error { return refused }); !errors.Is(err, refused) || got != nil {
				t.Fatalf("refused reservation: %q, %v", got, err)
			}
		})
	}
}
