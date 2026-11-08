package helpers

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

func TestSafeBodyStructureLineCount(t *testing.T) {
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
			bs, _ := SafeBodyStructure([]byte(tc.data))
			if bs == nil {
				t.Fatal("SafeBodyStructure() = nil")
			}
			assertTextPartsHaveLineCount(t, bs)
		})
	}
}

// TestSafeBodyStructureWellFormedReportsNoFallback: callers log the error, so
// a message the extractor handles must not produce one.
func TestSafeBodyStructureWellFormedReportsNoFallback(t *testing.T) {
	wellFormed := "Content-Type: multipart/alternative; boundary=\"b\"\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nhello\r\n--b--\r\n"
	if bs, err := SafeBodyStructure([]byte(wellFormed)); err != nil {
		t.Fatalf("well-formed message reported a fallback: %v (%T)", err, bs)
	}
}

// TestSafeBodyStructurePanic covers the panic path: the recovery exists so that
// a message that blows up the MIME parser still gets a body structure. A bare
// recover() in a function with an unnamed result cannot set one, so this used
// to hand callers the nil that the FETCH write path panics on.
func TestSafeBodyStructurePanic(t *testing.T) {
	orig := ExtractBodyStructure
	ExtractBodyStructure = func(io.Reader) imap.BodyStructure {
		panic("malformed message")
	}
	defer func() { ExtractBodyStructure = orig }()

	bs, err := SafeBodyStructure([]byte("whatever"))
	if bs == nil {
		t.Fatal("SafeBodyStructure() = nil, want the fallback structure")
	}
	if err == nil {
		t.Fatal("SafeBodyStructure() reported no reason for the fallback")
	}
	assertTextPartsHaveLineCount(t, bs)
}

// TestSafeBodyStructureNil covers an extractor returning no structure at all.
func TestSafeBodyStructureNil(t *testing.T) {
	orig := ExtractBodyStructure
	ExtractBodyStructure = func(io.Reader) imap.BodyStructure { return nil }
	defer func() { ExtractBodyStructure = orig }()

	data := "whatever"
	bs, err := SafeBodyStructure([]byte(data))
	if bs == nil {
		t.Fatal("SafeBodyStructure() = nil, want the fallback structure")
	}
	if err == nil {
		t.Fatal("SafeBodyStructure() reported no reason for the fallback")
	}
	assertTextPartsHaveLineCount(t, bs)
	// The fallback describes the whole message as text/plain of its size.
	if sp, ok := bs.(*imap.BodyStructureSinglePart); !ok || sp.Type != "text" || sp.Subtype != "plain" {
		t.Fatalf("fallback = %#v; want text/plain", bs)
	} else if int(sp.Size) != len(data) {
		t.Fatalf("fallback size = %d; want the message size %d", sp.Size, len(data))
	}
}

// A multipart whose declared boundary never appears gets the extractor's
// synthetic child, so FETCH has something to serialize, while the attachment
// classifier must not read that child as a successful MIME parse.
func TestSafeBodyStructureMalformedMultipartStaysUnknownToClassifier(t *testing.T) {
	raw := []byte("Content-Type: multipart/mixed; boundary=declared\r\n\r\n" +
		"--actual\r\nContent-Type: text/plain\r\n\r\nbody\r\n--actual--\r\n")
	if bs, _ := SafeBodyStructure(raw); bs == nil {
		t.Fatal("malformed mail still needs a serializable body structure")
	}
	if _, known := AttachmentKeyword(raw); known {
		t.Fatal("the extractor's synthetic multipart child must not count as a successful MIME parse")
	}
}
