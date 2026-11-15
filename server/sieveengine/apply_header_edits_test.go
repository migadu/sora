package sieveengine

import (
	"bufio"
	"bytes"
	"context"
	"slices"
	"testing"

	"github.com/emersion/go-message/textproto"
)

// TestApplyHeaderEditsFieldOrder is issue #1585: the edits were applied through
// go-message's Header, whose Add prepends to the fields of that name, and every
// "delete" re-added the surviving fields one by one, so addheader without :last
// landed below the fields of its name, :last landed at the top of the header, and
// deleteheader reversed the remaining fields and moved them to the top.
//
// RFC 5293 §4: "By default, the header field is inserted at the beginning of the
// existing message header.  If the optional flag ":last" is specified, it is
// appended at the end." §5: "If :last is specified, the count is backwards; 1
// denotes the last named header field".
func TestApplyHeaderEditsFieldOrder(t *testing.T) {
	const (
		received = "Received: r1\r\n"
		fooA     = "X-Foo: a\r\n"
		subject  = "Subject: s\r\n"
		fooB     = "X-Foo: b\r\n"
		to       = "To: user@example.com\r\n"
		body     = "\r\nbody\r\n"
		raw      = received + fooA + subject + fooB + to + body
	)
	for _, tc := range []struct {
		name  string
		raw   string
		edits []HeaderEdit
		want  string
	}{
		{
			name:  "addheader inserts at the top",
			edits: []HeaderEdit{{Action: "add", FieldName: "X-Foo", Value: "new-first"}},
			want:  "X-Foo: new-first\r\n" + raw,
		},
		{
			name:  "addheader :last appends at the end",
			edits: []HeaderEdit{{Action: "add", FieldName: "X-New", Value: "new-last", Last: true}},
			want:  received + fooA + subject + fooB + to + "X-New: new-last\r\n" + body,
		},
		{
			name:  "deleteheader :index 1",
			edits: []HeaderEdit{{Action: "delete", FieldName: "X-Foo", Index: 1}},
			want:  received + subject + fooB + to + body,
		},
		{
			name:  "deleteheader :index 1 :last",
			edits: []HeaderEdit{{Action: "delete", FieldName: "X-Foo", Index: 1, Last: true}},
			want:  received + fooA + subject + to + body,
		},
		{
			name:  "deleteheader :index past the fields",
			edits: []HeaderEdit{{Action: "delete", FieldName: "X-Foo", Index: 3}},
			want:  raw,
		},
		{
			name:  "deleteheader with a value-pattern",
			edits: []HeaderEdit{{Action: "delete", FieldName: "X-Foo", Value: "a"}},
			want:  received + subject + fooB + to + body,
		},
		{
			name:  "deleteheader of every field",
			edits: []HeaderEdit{{Action: "delete", FieldName: "x-foo"}},
			want:  received + subject + to + body,
		},
		{
			// The edits apply in order, each to the header the earlier ones left,
			// as the script saw it: :index 1 is now the field just added.
			name: "deleteheader counts the fields earlier edits added",
			edits: []HeaderEdit{
				{Action: "add", FieldName: "X-Foo", Value: "new-first"},
				{Action: "add", FieldName: "X-Foo", Value: "new-last", Last: true},
				{Action: "delete", FieldName: "X-Foo", Index: 2},
				{Action: "delete", FieldName: "X-Foo", Index: 2, Last: true},
			},
			want: "X-Foo: new-first\r\n" + received + subject + to + "X-Foo: new-last\r\n" + body,
		},
		{
			// A folded field is deleted with its continuation lines, and the
			// value it is selected by is the unfolded one the script saw.
			name:  "deleteheader of a folded field",
			raw:   received + "X-Foo: a\r\n\tcontinued\r\n" + subject + "X-Foo: a\r\n  continued \r\n" + to + body,
			edits: []HeaderEdit{{Action: "delete", FieldName: "X-Foo", Value: "a continued"}},
			want:  received + subject + "X-Foo: a\r\n  continued \r\n" + to + body,
		},
		{
			name:  "bare LF line endings",
			raw:   "Subject: s\nX-Foo: a\n\nbody\n",
			edits: []HeaderEdit{{Action: "add", FieldName: "X-New", Value: "v"}, {Action: "add", FieldName: "X-End", Value: "e", Last: true}},
			want:  "X-New: v\nSubject: s\nX-Foo: a\nX-End: e\n\nbody\n",
		},
		{
			name:  "header without a blank line or final line break",
			raw:   "Subject: s\r\nX-Foo: a",
			edits: []HeaderEdit{{Action: "add", FieldName: "X-End", Value: "e", Last: true}},
			want:  "Subject: s\r\nX-Foo: a\r\nX-End: e\r\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.raw
			if in == "" {
				in = raw
			}
			got, err := ApplyHeaderEdits([]byte(in), tc.edits)
			if err != nil {
				t.Fatalf("ApplyHeaderEdits: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("edited message:\n%q\nwant:\n%q", got, tc.want)
			}
		})
	}
}

// TestApplyHeaderEditsKeepsOtherBytes is the rest of issue #1585: applying an edit
// re-serialised the whole message through go-message, which added
// "Mime-Version: 1.0" and transfer-decoded and re-encoded the body (a
// quoted-printable soft line break was reflowed, a base64 body lost its final
// line break), so touching one X- field changed the bytes a DKIM signature covers.
// A message whose charset go-message does not know could not be edited at all.
func TestApplyHeaderEditsKeepsOtherBytes(t *testing.T) {
	deleteFoo := []HeaderEdit{{Action: "delete", FieldName: "X-Foo"}}
	for _, tc := range []struct {
		name   string
		header string // the fields other than X-Foo
		body   string
	}{
		{
			name:   "quoted-printable",
			header: "From: sender@example.org\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n",
			body:   "short=\r\n line caf=C3=A9 =3D x\r\n",
		},
		{
			name:   "base64",
			header: "From: sender@example.org\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n",
			body:   "aGVsbG8gd29ybGQ=\r\n",
		},
		{
			name:   "multipart",
			header: "From: sender@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n",
			body:   "preamble\r\n--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nsoft=\r\n break\r\n--b--\r\nepilogue\r\n",
		},
		{
			name:   "unknown charset",
			header: "From: sender@example.org\r\nContent-Type: text/plain; charset=x-unknown\r\n",
			body:   "body\r\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := "X-Foo: a\r\n" + tc.header + "\r\n" + tc.body
			got, err := ApplyHeaderEdits([]byte(raw), deleteFoo)
			if err != nil {
				t.Fatalf("ApplyHeaderEdits: %v", err)
			}
			if want := tc.header + "\r\n" + tc.body; string(got) != want {
				t.Errorf("edited message:\n%q\nwant:\n%q", got, want)
			}
		})
	}
}

// TestApplyHeaderEditsFromScript applies the edits a script records, as LMTP and
// the Admin API delivery do: the stored message must have the header the script's
// own tests saw after its edits. RFC 5293 §7: "All other actions that store, send,
// or alter the message MUST do so with the current set of header fields."
func TestApplyHeaderEditsFromScript(t *testing.T) {
	const script = `require ["editheader", "fileinto"];
addheader "X-Foo" "new-first";
addheader :last "X-New" "new-last";
deleteheader :index 1 :last "X-Foo";
deleteheader :contains "X-Bar" "drop";
if header :is "X-Foo" "new-first" { fileinto "seen"; }
`
	extensions := EffectiveExtensions(append(slices.Clone(DefaultSieveExtensions), "editheader"))
	executor, err := NewSieveExecutorWithExtensions(script, extensions)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	raw := "Received: r1\r\n" +
		"X-Foo: a\r\n" +
		"X-Bar: keep\r\n" +
		"Subject: s\r\n" +
		"X-Bar: drop me\r\n" +
		"X-Foo: b\r\n" +
		"To: user@example.com\r\n" +
		"\r\nbody\r\n"
	result, err := executor.Evaluate(context.Background(), rawContext(t, raw))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !slices.Equal(result.Mailboxes, []string{"seen"}) {
		t.Errorf("mailboxes = %q, want [\"seen\"]", result.Mailboxes)
	}
	got, err := ApplyHeaderEdits([]byte(raw), result.HeaderEdits)
	if err != nil {
		t.Fatalf("ApplyHeaderEdits: %v", err)
	}
	want := "X-Foo: new-first\r\n" +
		"Received: r1\r\n" +
		"X-Foo: a\r\n" +
		"X-Bar: keep\r\n" +
		"Subject: s\r\n" +
		"To: user@example.com\r\n" +
		"X-New: new-last\r\n" +
		"\r\nbody\r\n"
	if string(got) != want {
		t.Errorf("edited message:\n%q\nwant:\n%q", got, want)
	}
}

// FuzzParseHeaderFields checks that ApplyHeaderEdits sees the fields the script
// saw: the script's header map comes from go-message, and a value-pattern
// deleteheader selects a field by the value go-message gave it. An edit that
// changes nothing leaves the message as it is.
func FuzzParseHeaderFields(f *testing.F) {
	for _, seed := range []string{
		"A: b\r\n c\r\nD :  e \r\n\t\r\nF:\r\n\r\nbody",
		"A: b\nC: d\n\nx",
		"A: b\r\r\nC: \r d\r\n",
		":\r",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, msg []byte) {
		h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(msg)))
		if err != nil {
			return // delivery refuses a message whose header go-message cannot read
		}
		fields := parseHeaderFields(msg[:headerEnd(msg)])
		if len(fields) != h.Len() {
			t.Fatalf("%q: %d fields, go-message reads %d", msg, len(fields), h.Len())
		}
		i := 0
		for fs := h.Fields(); fs.Next(); i++ {
			if key, value := lowerASCII(fs.Key()), fs.Value(); fields[i].key != key || fields[i].value != value {
				t.Fatalf("%q: field %d is %q: %q, go-message reads %q: %q", msg, i, fields[i].key, fields[i].value, key, value)
			}
		}
		got, err := ApplyHeaderEdits(msg, []HeaderEdit{{Action: "delete", FieldName: "X-Absent"}})
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("%q: an edit that matches nothing gave %q, %v", msg, got, err)
		}
	})
}
