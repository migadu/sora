package helpers

import (
	"strings"
	"testing"

	"github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
)

func TestExtractMessageIDRaw(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	cases := []struct {
		name string
		raw  string
		want *string
	}{
		{
			name: "absent Message-ID",
			raw:  "From: a@example.com\r\nSubject: test\r\n\r\nbody\r\n",
			want: nil,
		},
		{
			name: "canonical single Message-ID omitted",
			raw:  "From: a@example.com\r\nMessage-ID: <Support@Example.COM>\r\n\r\nbody\r\n",
			want: nil,
		},
		{
			name: "folded canonical single Message-ID omitted",
			raw:  "From: a@example.com\r\nMessage-ID:\r\n <Support@Example.COM>\r\n\r\nbody\r\n",
			want: nil,
		},
		{
			name: "surrounding CFWS comment retained",
			raw:  "From: a@example.com\r\nMessage-ID: (NeedleComment) <comm@example.com>\r\n\r\nbody\r\n",
			want: strPtr("(NeedleComment) <comm@example.com>"),
		},
		{
			name: "present-empty Message-ID retained as empty string",
			raw:  "From: a@example.com\r\nMessage-ID:\r\n\r\nbody\r\n",
			want: strPtr(""),
		},
		{
			name: "malformed Message-ID retained",
			raw:  "From: a@example.com\r\nMessage-ID: malformed\r\n\r\nbody\r\n",
			want: strPtr("malformed"),
		},
		{
			name: "nested bracket domain-literal retained",
			raw:  "From: a@example.com\r\nMessage-ID: <outer@[<inner@example.com>]>\r\n\r\nbody\r\n",
			want: strPtr("<outer@[<inner@example.com>]>"),
		},
		{
			// go-message keeps quoting the local part needs, so "<" + message_id + ">"
			// reproduces the field and the search loses nothing.
			name: "required local-part quoting omitted",
			raw:  "From: a@example.com\r\nMessage-ID: <\"<inner\"@example.com>\r\n\r\nbody\r\n",
			want: nil,
		},
		{
			// go-message drops quoting the local part does not need (RFC 5256
			// section 2.2.2), so the field text differs from message_id.
			name: "unnecessary local-part quoting retained",
			raw:  "From: a@example.com\r\nMessage-ID: <\"quoted\"@example.com>\r\n\r\nbody\r\n",
			want: strPtr("<\"quoted\"@example.com>"),
		},
		{
			name: "multiple Message-ID fields joined by newline",
			raw:  "From: a@example.com\r\nMessage-ID: <first@example.com>\r\nMessage-ID: <second@example.com>\r\n\r\nbody\r\n",
			want: strPtr("<first@example.com>\n<second@example.com>"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := message.Read(strings.NewReader(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			mh := mail.Header{Header: e.Header}
			parsedID, _ := mh.MessageID()
			got := ExtractMessageIDRaw(e.Header, parsedID)
			if (got == nil) != (tc.want == nil) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			if got != nil && *got != *tc.want {
				t.Fatalf("got %q, want %q", *got, *tc.want)
			}
		})
	}
}

func TestExtractRawMessageIDFromBytesDegraded(t *testing.T) {
	raw := []byte("From: a@example.com\r\nMalformedHeaderWithoutColon\r\nmEsSaGe-Id: (Folded\r\n Comment) <deg@example.com>\r\n\r\nMessage-ID: <in-body@example.com>\r\n")
	got := ExtractRawMessageIDFromBytes(raw)
	if got == nil || *got != "(Folded Comment) <deg@example.com>" {
		t.Fatalf("got %v, want %q", got, "(Folded Comment) <deg@example.com>")
	}

	if none := ExtractRawMessageIDFromBytes([]byte("From: a@example.com\r\nMalformedLine\r\n\r\nMessage-ID: <body@example.com>\r\n")); none != nil {
		t.Fatalf("expected nil when Message-ID only appears in body, got %q", *none)
	}
}

// Folding keeps each physical line below RFC 5322's limit; the total field body
// still has no 16 KiB protocol limit. A later duplicate field must also survive.
func TestMessageIDRawRetainsLongFoldedFieldsAndLaterDuplicates(t *testing.T) {
	const tail = "TailNeedleBeyondSixteenKiB"
	value := "(" + strings.Repeat(strings.Repeat("x", 900)+"\r\n ", 20) + tail + ") <long@example.com>"
	raw := "From: a@example.com\r\nMessage-ID: " + value + "\r\nMessage-ID: <later@example.com>\r\n\r\nbody\r\n"
	e, err := message.Read(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mh := mail.Header{Header: e.Header}
	parsedID, _ := mh.MessageID()
	for name, got := range map[string]*string{
		"structured": ExtractMessageIDRaw(e.Header, parsedID),
		"degraded":   ExtractRawMessageIDFromBytes([]byte(raw)),
	} {
		if got == nil || !strings.Contains(*got, tail) || !strings.Contains(*got, "<later@example.com>") {
			t.Errorf("%s lost the tail of a valid folded field or a later duplicate", name)
		}
	}
	if got := SanitizeMessageIDRaw(&value); !strings.Contains(*got, tail) {
		t.Error("storage sanitizer silently truncated the field")
	}
}
