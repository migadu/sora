package helpers

import (
	"bytes"
	"errors"
	"runtime"
	"strings"
	"testing"

	imap "github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
)

// nulPartsSections is what FETCH BODY[part] and BINARY[part] send for msg, via
// the same go-imap extraction FETCH uses.
func nulPartsSections(t *testing.T, msg []byte, part ...int) (body, binary []byte) {
	t.Helper()
	body = imapserver.ExtractBodySection(bytes.NewReader(msg), &imap.FetchItemBodySection{Part: part})
	binary, err := imapserver.DecodeBinarySection(bytes.NewReader(msg), &imap.FetchItemBinarySection{Part: part})
	if err != nil {
		t.Fatalf("BINARY%v: %v", part, err)
	}
	return body, binary
}

func TestEncodeNULParts(t *testing.T) {
	const nulBody = "\x00-\xe4\n\r\n\n"
	long := strings.Repeat("\x00\x01\x02", 40) // 120 octets: three base64 lines

	for _, tc := range []struct {
		name string
		msg  string
		part []int
		want string // decoded content of part
	}{
		{
			name: "single part binary (imaptest append-binary)",
			msg: "From: user@domain.org\r\nMime-Version: 1.0\r\nContent-Type: application/octet-stream\r\n" +
				"Content-Transfer-Encoding: binary\r\n\r\n" + nulBody,
			part: []int{1},
			want: nulBody,
		},
		{
			name: "no Content-Transfer-Encoding field",
			msg:  "From: a@example.com\r\nContent-Type: application/octet-stream\r\n\r\n" + long,
			part: []int{1},
			want: long,
		},
		{
			name: "folded field and bare LF",
			msg:  "From: a@example.com\nContent-Transfer-Encoding:\n binary\nContent-Type: application/octet-stream\n\n" + nulBody,
			part: []int{1},
			want: nulBody,
		},
		{
			name: "multipart leaf",
			msg: "From: a@example.com\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n" +
				"preamble\r\n--b1\r\nContent-Type: text/plain\r\n\r\nhello\r\n" +
				"--b1\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + long + "\r\n" +
				"--b1--\r\nepilogue\r\n",
			part: []int{2},
			want: long,
		},
		{
			name: "inside message/rfc822",
			msg: "From: a@example.com\r\nContent-Type: multipart/mixed; boundary=b1\r\n\r\n" +
				"--b1\r\nContent-Type: message/rfc822\r\n\r\n" +
				"From: c@example.com\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n" + nulBody + "\r\n" +
				"--b1--\r\n",
			part: []int{1, 1},
			want: nulBody,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := encodeNULPartsChecked(t, []byte(tc.msg))
			if !changed {
				t.Fatal("EncodeNULParts reported no change")
			}
			if bytes.IndexByte(got, 0) >= 0 {
				t.Fatalf("NUL left in:\n%q", got)
			}
			body, binary := nulPartsSections(t, got, tc.part...)
			if len(body) == 0 || bytes.IndexByte(body, 0) >= 0 {
				t.Fatalf("BODY%v = %q", tc.part, body)
			}
			if string(binary) != tc.want {
				t.Fatalf("BINARY%v = %q, want %q (message %q)", tc.part, binary, tc.want, got)
			}
			if n := bytes.Count(got, []byte("Content-Transfer-Encoding")); n != 1 {
				t.Fatalf("%d Content-Transfer-Encoding fields, want 1:\n%q", n, got)
			}
			for _, line := range strings.Split(string(got), "\n") {
				if len(strings.TrimSuffix(line, "\r")) > 76 && !strings.Contains(tc.msg, line) {
					t.Fatalf("base64 line longer than 76: %q", line)
				}
			}
		})
	}

	t.Run("everything outside the part kept", func(t *testing.T) {
		before := "From: a@example.com\r\nContent-Type: multipart/mixed; boundary=b1\r\n\r\n" +
			"preamble\r\n--b1\r\nContent-Type: text/plain\r\n\r\nhello\r\n" +
			"--b1 \r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\nX-A: 1\r\n\r\n"
		after := "\r\n--b1--\r\nepilogue\r\n"
		got, _ := encodeNULPartsChecked(t, []byte(before+nulBody+after))
		want := strings.Replace(before, "Content-Transfer-Encoding: binary", "Content-Transfer-Encoding: base64", 1) +
			"AC3kCg0KCg==" + after
		if string(got) != want {
			t.Fatalf("got\n%q\nwant\n%q", got, want)
		}
	})

	for _, tc := range []struct{ name, msg string }{
		{"no NUL", "From: a@example.com\r\nContent-Transfer-Encoding: binary\r\n\r\n\x01\xff\r\n"},
		{"NUL only in the header", "From: a\x00@example.com\r\n\r\nbody\r\n"},
		{"already base64", "From: a@example.com\r\nContent-Transfer-Encoding: base64\r\n\r\nAA\x00==\r\n"},
		{"NUL only in the preamble", "Content-Type: multipart/mixed; boundary=b1\r\n\r\n\x00\r\n--b1\r\n\r\nx\r\n--b1--\r\n"},
		{"no body", "From: a@example.com\r\nX-A: \x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := encodeNULPartsChecked(t, []byte(tc.msg))
			if changed || string(got) != tc.msg {
				t.Fatalf("changed=%v, got %q", changed, got)
			}
		})
	}
}

// encodeNULPartsChecked runs EncodeNULParts and checks its reservation contract:
// reserve is called only when the message changes, with exactly the size of the
// buffer then allocated, and an unchanged message is returned without a copy.
func encodeNULPartsChecked(t *testing.T, msg []byte) ([]byte, bool) {
	t.Helper()
	reserved, calls := int64(0), 0
	got, changed, err := EncodeNULParts(msg, func(size int64) error {
		reserved, calls = size, calls+1
		return nil
	})
	if err != nil {
		t.Fatalf("EncodeNULParts: %v", err)
	}
	if !changed {
		if calls != 0 {
			t.Fatalf("reserve called %d times for an unchanged message", calls)
		}
		if len(msg) > 0 && &got[0] != &msg[0] {
			t.Fatal("unchanged message was copied")
		}
		return got, changed
	}
	if calls != 1 || reserved != int64(len(got)) || int64(cap(got)) != reserved {
		t.Fatalf("reserve called %d times for %d bytes; output is %d bytes in a %d-byte buffer", calls, reserved, len(got), cap(got))
	}
	return got, changed
}

// A refused reservation allocates nothing the size of the message and returns
// the reserve error as it is.
func TestEncodeNULPartsReserveRefused(t *testing.T) {
	msg := []byte("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n" +
		strings.Repeat("\x00\xff\r\n", 100000))
	want, _ := encodeNULPartsChecked(t, msg)
	refused := errors.New("over budget")
	var asked int64
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	got, changed, err := EncodeNULParts(msg, func(size int64) error {
		asked = size
		return refused
	})
	runtime.ReadMemStats(&after)
	if !errors.Is(err, refused) || got != nil || changed {
		t.Fatalf("got %d bytes, changed=%v, err=%v; want the reserve error and no output", len(got), changed, err)
	}
	if asked != int64(len(want)) {
		t.Fatalf("reserve asked for %d bytes, the encoded message is %d", asked, len(want))
	}
	// The size pass parses the header (a bufio.Reader and the fields) and
	// nothing else: far less than the %d-byte output it refused.
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<10 {
		t.Fatalf("refused reservation allocated %d bytes (encoded size %d)", allocated, len(want))
	}
}
