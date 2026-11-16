package imap

import (
	"testing"

	"github.com/migadu/go-imap"
)

// TestFetch_HeaderFieldsNotFoldsNonTokenNames covers BODY[HEADER.FIELDS.NOT (...)]
// for a field-name holding a byte that RFC 5322 §3.6.8 allows (any printable
// US-ASCII but ":") but that is no HTTP token character, such as "(". RFC 9051
// §6.4.5: "The field-matching is ASCII-range case insensitive but is otherwise
// exact", so every ASCII case variant of the name is removed.
func TestFetch_HeaderFieldsNotFoldsNonTokenNames(t *testing.T) {
	body := []byte("From: a@example.com\r\nX(a: 1\r\nx(A: 2\r\nSubject: s\r\n\r\nbody\r\n")

	for _, tc := range []struct {
		fieldsNot []string
		want      string
	}{
		{[]string{"x(a"}, "From: a@example.com\r\nSubject: s\r\n\r\n"},
		{[]string{"X(A"}, "From: a@example.com\r\nSubject: s\r\n\r\n"},
		{[]string{"SUBJECT"}, "From: a@example.com\r\nX(a: 1\r\nx(A: 2\r\n\r\n"},
	} {
		got, _ := safeExtractBodySection(body, &imap.FetchItemBodySection{
			Specifier:       imap.PartSpecifierHeader,
			HeaderFieldsNot: tc.fieldsNot,
			Peek:            true,
		})
		if string(got) != tc.want {
			t.Errorf("BODY.PEEK[HEADER.FIELDS.NOT %q] = %q, want %q", tc.fieldsNot, got, tc.want)
		}
	}
}
