package imap

import (
	"io"
	"testing"

	"github.com/emersion/go-imap/v2"
)

// assertTextPartsHaveLineCount walks a body structure and fails if any text part
// is missing its line count.
//
// body-fld-lines is mandatory for a text part (RFC 9051 body-type-text). A text
// part with no line count is serialized with the extension section where the
// count belongs -- ("text" "plain" NIL NIL NIL "7bit" 1234 NIL NIL NIL NIL) --
// and clients fail the entire FETCH response on it, taking down every other
// message in the same response. Fallback structures declare themselves
// text/plain, so they are the ones that have to remember the count.
func assertTextPartsHaveLineCount(t *testing.T, bs imap.BodyStructure) {
	t.Helper()
	switch v := bs.(type) {
	case *imap.BodyStructureSinglePart:
		if v.Type == "text" && v.Text == nil {
			t.Errorf("%v/%v part has no line count", v.Type, v.Subtype)
		}
		if v.MessageRFC822 != nil && v.MessageRFC822.BodyStructure != nil {
			assertTextPartsHaveLineCount(t, v.MessageRFC822.BodyStructure)
		}
	case *imap.BodyStructureMultiPart:
		for _, child := range v.Children {
			assertTextPartsHaveLineCount(t, child)
		}
	default:
		t.Fatalf("unexpected body structure type %T", bs)
	}
}

func TestExtractBodyStructureSafeLineCount(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{"empty", ""},
		{"headers only", "Subject: hi\r\n\r\n"},
		{"no headers", "just a bare line of text\r\n"},
		{"binary garbage", "\x00\x01\x02\xff\xfe not a message at all"},
		{
			name: "multipart with a boundary that never matches",
			data: "Content-Type: multipart/mixed; boundary=\"nonexistent\"\r\n" +
				"\r\n" +
				"This is not a valid MIME part.\r\n",
		},
		{
			name: "well-formed multipart",
			data: "Content-Type: multipart/alternative; boundary=\"b\"\r\n" +
				"\r\n" +
				"--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n" +
				"--b\r\nContent-Type: text/html\r\n\r\n<p>hello</p>\r\n" +
				"--b--\r\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bs := extractBodyStructureSafe([]byte(tc.data))
			if bs == nil {
				t.Fatal("extractBodyStructureSafe() = nil")
			}
			assertTextPartsHaveLineCount(t, bs)
		})
	}
}

// TestExtractBodyStructureSafePanic covers the panic path: the recovery exists
// so that a message that blows up the MIME parser still gets a body structure.
// A bare recover() in a function with an unnamed result cannot set one, so this
// used to hand callers the nil that the FETCH write path panics on.
func TestExtractBodyStructureSafePanic(t *testing.T) {
	orig := extractBodyStructure
	extractBodyStructure = func(io.Reader) imap.BodyStructure {
		panic("malformed message")
	}
	defer func() { extractBodyStructure = orig }()

	bs := extractBodyStructureSafe([]byte("whatever"))
	if bs == nil {
		t.Fatal("extractBodyStructureSafe() = nil, want the fallback structure")
	}
	assertTextPartsHaveLineCount(t, bs)
}

// TestExtractBodyStructureSafeNil covers a backend returning no structure at all.
func TestExtractBodyStructureSafeNil(t *testing.T) {
	orig := extractBodyStructure
	extractBodyStructure = func(io.Reader) imap.BodyStructure { return nil }
	defer func() { extractBodyStructure = orig }()

	bs := extractBodyStructureSafe([]byte("whatever"))
	if bs == nil {
		t.Fatal("extractBodyStructureSafe() = nil, want the fallback structure")
	}
	assertTextPartsHaveLineCount(t, bs)
}
