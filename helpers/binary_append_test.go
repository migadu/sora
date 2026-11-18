package helpers

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/migadu/go-imap"
	"github.com/migadu/go-imap/imapserver"
)

func TestNormalizeBinaryAppendLeaf(t *testing.T) {
	for _, encoding := range []string{"binary", "BiNaRy (original)", "8bit", "7bit", ""} {
		t.Run(encoding, func(t *testing.T) {
			prefix := "From: sender@example.test\r\nSubject: =?utf-8?Q?caf=C3=A9?=\r\nX-Raw: preserve\t spaces\r\n\tfolding\r\nContent-Type: application/octet-stream\r\n"
			cte := ""
			if encoding != "" {
				cte = "Content-Transfer-Encoding: " + encoding + "\r\n"
			}
			payload := []byte{0, '-', 0xe4, '\n', '\r', '\n', '\n'}
			raw := append([]byte(prefix+cte+"\r\n"), payload...)
			original := bytes.Clone(raw)
			calls := 0
			var reserved int64
			got, err := NormalizeBinaryAppend(raw, func(n int64) error { calls++; reserved = n; return nil })
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(raw, original) {
				t.Fatal("mutated input")
			}
			if calls != 1 || reserved != int64(len(got)) {
				t.Fatalf("reservation %d/%d; output %d", calls, reserved, len(got))
			}
			want := prefix + "Content-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(payload)
			if string(got) != want {
				t.Fatalf("got %q, want %q", got, want)
			}
			decoded, err := imapserver.DecodeBinarySection(bytes.NewReader(got), &imap.FetchItemBinarySection{Part: []int{1}})
			if err != nil || !bytes.Equal(decoded, payload) {
				t.Fatalf("decoded %q, %v", decoded, err)
			}
		})
	}
}

func TestNormalizeBinaryAppendPreservesSafeInput(t *testing.T) {
	for _, raw := range []string{
		"Subject: safe\r\nContent-Transfer-Encoding: base64\r\n\r\nYQBi/w==\r\n",
		"Subject: safe\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\na=00b=FF\r\n",
		"Subject: safe\r\nContent-Transfer-Encoding: x-private\r\n\r\nopaque safely stored bytes\r\n",
		"Content-Type: message/x-private\r\nContent-Transfer-Encoding: 7bit\r\n\r\nsafe opaque message data\r\n",
		"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\u00a0\r\n\r\nsafe opaque body",
		"Subject: safe\r\n\r\nordinary body\r\n",
	} {
		input := []byte(raw)
		got, err := NormalizeBinaryAppend(input, func(int64) error { t.Fatal("reserved unchanged bytes"); return nil })
		if err != nil {
			t.Fatal(err)
		}
		if len(got) > 0 && &got[0] != &input[0] {
			t.Fatal("copied unchanged input")
		}
		if !bytes.Equal(got, input) {
			t.Fatal("changed safe content")
		}
	}
}

func TestNormalizeBinaryAppendDeclaredBinaryWithoutNUL(t *testing.T) {
	raw := []byte("Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: binary\r\n\r\ncaf\xe9")
	got, err := NormalizeBinaryAppend(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got, []byte("charset=iso-8859-1")) {
		t.Fatal("changed charset")
	}
	decoded, err := imapserver.DecodeBinarySection(bytes.NewReader(got), &imap.FetchItemBinarySection{Part: []int{1}})
	if err != nil || !bytes.Equal(decoded, []byte("caf\xe9")) {
		t.Fatalf("charset conversion changed bytes: %q, %v", decoded, err)
	}
}

func TestNormalizeBinaryAppendMultipartPreservesRawRegions(t *testing.T) {
	untouched := "Content-Type: application/pgp-signature\r\nX-Keep: two  spaces\r\n\r\nsigned\r\nbytes\r\n"
	prefix := "Subject: mixed\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\npreamble\r\n--outer\r\n" + untouched + "\r\n--outer\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\ninner preamble\r\n--inner\r\nContent-Type: application/octet-stream\r\n"
	suffix := "\r\n--inner-- \t\r\ninner epilogue\r\n--outer--\r\nouter epilogue"
	payload := []byte("a\x00b\r\n")
	raw := []byte(prefix + "Content-Transfer-Encoding: binary\r\n\r\n" + string(payload) + suffix)
	want := []byte(prefix + "Content-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString(payload) + suffix)
	got, err := NormalizeBinaryAppend(raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unrelated MIME regions changed:\ngot  %q\nwant %q", got, want)
	}
	decoded, err := imapserver.DecodeBinarySection(bytes.NewReader(got), &imap.FetchItemBinarySection{Part: []int{2, 1}})
	if err != nil || !bytes.Equal(decoded, payload) {
		t.Fatalf("nested payload %q, %v", decoded, err)
	}
}

func TestNormalizeBinaryAppendEmbeddedMessage(t *testing.T) {
	payload := []byte("raw\x00\xff\r\n")
	child := "From: nested@example.test\r\nSubject: attached\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n"
	prefix := "Content-Type: message/rfc822\r\nContent-Transfer-Encoding: binary\r\n\r\n"
	got, err := NormalizeBinaryAppend([]byte(prefix+child+string(payload)), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(prefix, "binary", "8bit", 1) + strings.Replace(child, "binary", "base64", 1) + base64.StdEncoding.EncodeToString(payload)
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	decoded, err := imapserver.DecodeBinarySection(bytes.NewReader(got), &imap.FetchItemBinarySection{Part: []int{1, 1}})
	if err != nil || !bytes.Equal(decoded, payload) {
		t.Fatalf("embedded payload %q, %v", decoded, err)
	}
}

func TestNormalizeBinaryAppendDigestDefaultsAndEmptyLeaves(t *testing.T) {
	// A headerless digest child defaults to message/rfc822, whose own message
	// contains two leaves, including an empty one explicitly labeled binary.
	raw := "Content-Type: multipart/digest; boundary=outer\r\nContent-Transfer-Encoding: binary\r\n\r\n--outer\r\n\r\n" +
		"From: nested@example.test\r\nContent-Type: multipart/mixed; boundary=inner\r\n\r\n--inner\r\n" +
		"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n\r\n--inner\r\n" +
		"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\nx\x00\r\n--inner--\r\n\r\n--outer--\r\n"
	got, err := NormalizeBinaryAppend([]byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(got, []byte("Content-Transfer-Encoding: binary")) || bytes.IndexByte(got, 0) >= 0 {
		t.Fatalf("unsafe binary representation remains: %q", got)
	}
	if !bytes.Contains(got, []byte("Content-Transfer-Encoding: base64\r\n\r\n\r\n--inner")) {
		t.Fatal("empty binary leaf or its separator changed")
	}
	if !bytes.Contains(got, []byte("Content-Transfer-Encoding: base64\r\n\r\neAA=\r\n--inner--")) {
		t.Fatalf("digest descendant was not encoded: %q", got)
	}
}

func TestNormalizeBinaryAppendFoldedMIMEHeaders(t *testing.T) {
	raw := "Subject: café\r\nContent-Type: multipart/mixed;\r\n\tboundary=\"b\"\r\n\r\n--b\r\n" +
		"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding:\r\n\tBiNaRy (comment)\r\nX-Preserve: folded\r\n value\r\n\r\nx\x00\r\n--b--"
	got, err := NormalizeBinaryAppend([]byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(raw, "Content-Transfer-Encoding:\r\n\tBiNaRy (comment)\r\n", "Content-Transfer-Encoding: base64\r\n", 1)
	want = strings.Replace(want, "x\x00\r\n--b--", "eAA=\r\n--b--", 1)
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNormalizeBinaryAppendFoldedQuotedBoundary(t *testing.T) {
	// Match the stored-message reader: it trims each folded line with ASCII
	// whitespace rules and joins them with one space, even in a quoted value.
	raw := "Content-Type: multipart/mixed; boundary=\"b\r\n\t  a\"\r\n\r\n--b a\r\n" +
		"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\nx\x00\r\n--b a--\r\n"
	got, err := NormalizeBinaryAppend([]byte(raw), nil)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := imapserver.DecodeBinarySection(bytes.NewReader(got), &imap.FetchItemBinarySection{Part: []int{1}})
	if err != nil || !bytes.Equal(decoded, []byte("x\x00")) {
		t.Fatalf("folded boundary chose a different part: %q, %v", decoded, err)
	}
}

func TestNormalizeBinaryAppendRejectsUnsafeInput(t *testing.T) {
	cases := map[string]string{
		"header NUL":                "Subject: bad\x00header\r\n\r\nbody",
		"unknown encoding":          "Content-Transfer-Encoding: x-private\r\n\r\nbody\x00",
		"encoded NUL":               "Content-Transfer-Encoding: base64\r\n\r\nYQ==\x00",
		"duplicate encoding":        "Content-Transfer-Encoding: binary\r\nContent-Transfer-Encoding: base64\r\n\r\nbody\x00",
		"invalid content type":      "Content-Type: multipart/mixed; boundary=\"unterminated\r\n\r\nbody\x00",
		"missing close boundary":    "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Transfer-Encoding: binary\r\n\r\nbody\x00",
		"preamble NUL":              "Content-Type: multipart/mixed; boundary=b\r\n\r\npre\x00amble\r\n--b\r\n\r\nbody\r\n--b--\r\n",
		"epilogue NUL":              "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nbody\r\n--b--\r\nepilogue\x00",
		"encoded container":         "Content-Type: multipart/mixed; boundary=b\r\nContent-Transfer-Encoding: base64\r\n\r\nraw\x00",
		"malformed header":          "Malformed\r\n\r\nraw\x00",
		"message subtype":           "Content-Type: message/x-private\r\nContent-Transfer-Encoding: binary\r\n\r\nraw\x00",
		"delivery status":           "Content-Type: message/delivery-status\r\nContent-Transfer-Encoding: binary\r\n\r\nstatus",
		"Unicode CTE whitespace":    "Content-Transfer-Encoding: binary\u00a0\r\n\r\nraw\x00",
		"encoded-word boundary":     "Content-Type: multipart/mixed; boundary=\"=?utf-8?B?Yg==?=\"\r\n\r\n--=?utf-8?B?Yg==?=\r\nContent-Transfer-Encoding: binary\r\n\r\nx\x00\r\n--=?utf-8?B?Yg==?=--\r\n",
		"content-type disagreement": "Content-Type: (comment) multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Transfer-Encoding: binary\r\n\r\nx\x00\r\n--b--\r\n",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := NormalizeBinaryAppend([]byte(raw), func(int64) error { t.Fatal("reserved unsafe output"); return nil })
			if !errors.Is(err, ErrBinaryAppendUnsafe) || got != nil {
				t.Fatalf("got %q, %v", got, err)
			}
		})
	}
}

func TestNormalizeBinaryAppendReservationFailure(t *testing.T) {
	cause := errors.New("reservation refused")
	got, err := NormalizeBinaryAppend([]byte("Content-Transfer-Encoding: binary\r\n\r\nraw\x00"), func(int64) error { return cause })
	if got != nil || !errors.Is(err, cause) || errors.Is(err, ErrBinaryAppendUnsafe) {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestNormalizeBinaryAppendRejectsEncodedContainers(t *testing.T) {
	for _, encoding := range []string{"base64", "quoted-printable", "x-private"} {
		t.Run(encoding, func(t *testing.T) {
			// Multipart readers ignore an invalid container CTE. Treating it as
			// an opaque safe leaf would expose its binary child in BODYSTRUCTURE.
			raw := "Content-Type: multipart/mixed; boundary=b\r\nContent-Transfer-Encoding: " + encoding +
				"\r\n\r\n--b\r\nContent-Transfer-Encoding: binary\r\n\r\nascii\r\n--b--\r\n"
			got, err := NormalizeBinaryAppend([]byte(raw), nil)
			if !errors.Is(err, ErrBinaryAppendUnsafe) || got != nil {
				t.Fatalf("encoded multipart returned %q, %v", got, err)
			}
		})
	}
}

func TestNormalizeBinaryAppendWrapsBase64Lines(t *testing.T) {
	payload := bytes.Repeat([]byte{0, 0xff, 'x'}, 91)
	got, err := NormalizeBinaryAppend(append([]byte("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n"), payload...), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, body, _ := bytes.Cut(got, []byte("\r\n\r\n"))
	for _, line := range bytes.Split(body, []byte("\r\n")) {
		if len(line) > 76 {
			t.Fatalf("base64 line has %d bytes", len(line))
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil || !bytes.Equal(decoded, payload) {
		t.Fatalf("payload differs: %v", err)
	}
}

func TestNormalizeBinaryAppendLimits(t *testing.T) {
	raw := "Content-Transfer-Encoding: binary\r\n\r\nx\x00"
	for i := 0; i < 70; i++ {
		raw = "Content-Type: message/rfc822\r\n\r\n" + raw
	}
	if _, err := NormalizeBinaryAppend([]byte(raw), nil); !errors.Is(err, ErrBinaryAppendUnsafe) {
		t.Fatalf("deep input: %v", err)
	}
	var multipart strings.Builder
	multipart.WriteString("Content-Type: multipart/mixed; boundary=b\r\n\r\n")
	for i := 0; i < 4200; i++ {
		multipart.WriteString("--b\r\n\r\nx\r\n")
	}
	multipart.WriteString("--b--\r\n")
	if _, err := NormalizeBinaryAppend([]byte(multipart.String()), nil); !errors.Is(err, ErrBinaryAppendUnsafe) {
		t.Fatalf("too many parts: %v", err)
	}
}

func FuzzNormalizeBinaryAppend(f *testing.F) {
	for _, seed := range []string{
		"Content-Transfer-Encoding: binary\r\n\r\na\x00b",
		"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\na\x00b\r\n--b--\r\n",
		"Content-Type: message/rfc822\r\n\r\nSubject: child\r\nContent-Transfer-Encoding: binary\r\n\r\n\x00",
		"Content-Transfer-Encoding: x-private\r\n\r\nopaque",
		"Malformed\r\n\r\n\x00",
		"\r\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			t.Skip("keep fuzz cases within the MIME header budget")
		}
		original := bytes.Clone(raw)
		calls := 0
		var reserved int64
		got, err := NormalizeBinaryAppend(raw, func(n int64) error {
			calls++
			reserved = n
			return nil
		})
		if !bytes.Equal(raw, original) {
			t.Fatal("mutated source")
		}
		if err != nil {
			if !errors.Is(err, ErrBinaryAppendUnsafe) || got != nil || calls != 0 {
				t.Fatalf("unsafe result %q, %v, reservations %d", got, err, calls)
			}
			return
		}
		if bytes.IndexByte(got, 0) >= 0 {
			t.Fatal("normalized output contains NUL")
		}
		if calls > 1 || calls == 1 && reserved != int64(len(got)) {
			t.Fatalf("reservation %d/%d, output %d", calls, reserved, len(got))
		}
		if calls == 0 && !bytes.Equal(got, raw) {
			t.Fatal("changed bytes without reserving output")
		}
	})
}

func FuzzNormalizeBinaryAppendLeafOctets(f *testing.F) {
	f.Add([]byte{0, '-', 0xe4, '\n', '\r', '\n', '\n'})
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{'x', 0, 0xff}, 100))
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 1<<20 {
			t.Skip("bound fuzz output allocation")
		}
		raw := append([]byte("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n"), payload...)
		got, err := NormalizeBinaryAppend(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, body, found := bytes.Cut(got, []byte("\r\n\r\n"))
		if !found {
			t.Fatal("lost MIME header terminator")
		}
		decoded, err := base64.StdEncoding.DecodeString(string(body))
		if err != nil || !bytes.Equal(decoded, payload) {
			t.Fatalf("decoded bytes changed: %v", err)
		}
	})
}
