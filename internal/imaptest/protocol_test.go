package imaptest

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestWireLiteralFraming(t *testing.T) {
	header := "Subject: literal\r\n\r\n"
	binary := "\x00\xff\r\nS123 OK fake\r\n)"
	wire := fmt.Sprintf("* 2 FETCH (UID 81 BODY[HEADER.FIELDS (SUBJECT)] {%d}\r\n%s BINARY[1] ~{%d}\r\n%s FLAGS (\\Seen))\r\nS000001 OK done\r\n", len(header), header, len(binary), binary)
	r := bufio.NewReaderSize(strings.NewReader(wire), 8)
	tag, reply, err := readReply(r)
	if err != nil {
		t.Fatal(err)
	}
	response := Response{Untagged: []Reply{reply}}
	fetches, err := response.Fetches()
	if err != nil {
		t.Fatal(err)
	}
	if tag != "*" || len(fetches) != 1 || fetches[0].Seq != 2 {
		t.Fatalf("unexpected FETCH framing: %q %#v", tag, fetches)
	}
	if got := fetches[0].Attrs["BODY[HEADER.FIELDS (SUBJECT)]"]; got.Text != header || !got.IsLiteral {
		t.Fatalf("header literal = %#v", got)
	}
	if got := fetches[0].Attrs["BINARY[1]"]; got.Text != binary || !got.IsLiteral {
		t.Fatalf("binary literal = %#v", got)
	}
	tag, completion, err := readReply(r)
	if err != nil || tag != "S000001" || completion.Status != "OK" {
		t.Fatalf("completion after binary literal: %q %#v %v", tag, completion, err)
	}
}

func TestWireStatusTextAndCodes(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("* OK [UIDVALIDITY 77] ready {123}\r\nA1 OK [READ-ONLY] selected\r\n"))
	_, first, err := readReply(r)
	if err != nil {
		t.Fatal(err)
	}
	tag, last, err := readReply(r)
	if err != nil {
		t.Fatal(err)
	}
	response := Response{Untagged: []Reply{first}, Completion: last}
	if tag != "A1" || first.Text != "ready {123}" {
		t.Fatalf("opaque status text incorrectly interpreted: %q %q", tag, first.Text)
	}
	code := response.Code("uidvalidity")
	if len(code) != 1 || code[0].Text != "77" {
		t.Fatalf("UIDVALIDITY code: %#v", code)
	}
	if response.Code("READ-ONLY") == nil || response.Code("ABSENT") != nil {
		t.Fatal("argument-free and absent response codes must be distinguishable")
	}
}

func TestWireNestedValuesAndQuotedEscapes(t *testing.T) {
	wire := "* LIST (\\HasNoChildren) \"/\" \"quote\\\" and \\\\ slash\"\r\n* 1 FETCH (ENVELOPE (\"date\" NIL ((\"name\" NIL \"user\" \"example.test\")) NIL NIL NIL NIL NIL NIL NIL))\r\n"
	r := bufio.NewReader(strings.NewReader(wire))
	_, list, err := readReply(r)
	if err != nil {
		t.Fatal(err)
	}
	if list.Kind() != "LIST" || list.Values[3].Text != "quote\" and \\ slash" {
		t.Fatalf("quoted LIST mailbox: %#v", list)
	}
	_, reply, err := readReply(r)
	if err != nil {
		t.Fatal(err)
	}
	fetches, err := (Response{Untagged: []Reply{reply}}).Fetches()
	if err != nil || len(fetches) != 1 || !fetches[0].Attrs["ENVELOPE"].IsList {
		t.Fatalf("nested envelope: %#v %v", fetches, err)
	}
}

func TestWireHeaderFieldSectionKeysAreSemantic(t *testing.T) {
	for _, tc := range []struct {
		key  string
		want string
	}{
		{`BODY[HEADER.FIELDS ("Subject")]`, `BODY[HEADER.FIELDS (SUBJECT)]`},
		{`body[1.header.fields.not ("Subject" From)]<0>`, `BODY[1.HEADER.FIELDS.NOT (FROM SUBJECT)]<0>`},
		{`BODY[HEADER.FIELDS (  SUBJECT   "from" Subject )]`, `BODY[HEADER.FIELDS (FROM SUBJECT)]`},
		{`BODY[HEADER.FIELDS ("X-]Header" "Subject")]`, `BODY[HEADER.FIELDS (SUBJECT "X-]HEADER")]`},
	} {
		wire := "* 1 FETCH (" + tc.key + " {2}\r\n\r\n)\r\n"
		_, reply, err := readReply(bufio.NewReader(strings.NewReader(wire)))
		if err != nil {
			t.Fatalf("parse %s: %v", tc.key, err)
		}
		fetches, err := (Response{Untagged: []Reply{reply}}).Fetches()
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := fetches[0].Attrs[tc.want]; !ok || got.Text != "\r\n" {
			t.Fatalf("section %s mapped to %v, want %s", tc.key, fetches[0].Attrs, tc.want)
		}
		if got := canonicalFetchAttribute(tc.want); got != tc.want {
			t.Fatalf("canonical key is not stable: %s -> %s", tc.want, got)
		}
	}
}

func TestWireRejectsMalformedOrUnboundedReplies(t *testing.T) {
	for _, wire := range []string{
		"* LIST () \"/\" \"unterminated\r\n",
		"* 1 FETCH (UID 1\r\n",
		"* 1 FETCH (BODY[] {99999999999999999999}\r\n",
		"* 1 FETCH (BODY[] {16777217}\r\n",
		"* 1 FETCH (BODY[] {8}\r\nshort",
		"* LIST () \"/\" foo\n",
		"* X " + strings.Repeat("(", 66) + strings.Repeat(")", 66) + "\r\n",
	} {
		_, _, err := readReply(bufio.NewReader(strings.NewReader(wire)))
		if err == nil {
			t.Fatalf("accepted malformed reply %.120q", wire)
		}
	}
}

func TestWireStatusLiteralAndSearchHelpers(t *testing.T) {
	wire := "* STATUS {5}\r\nINBOX (MESSAGES 2 UIDNEXT 90)\r\n* SEARCH 5 8 (MODSEQ 77)\r\n"
	r := bufio.NewReader(bytes.NewBufferString(wire))
	_, status, err := readReply(r)
	if err != nil {
		t.Fatal(err)
	}
	values, err := (Response{Untagged: []Reply{status}}).StatusValues("inbox")
	if err != nil || values["MESSAGES"] != 2 || values["UIDNEXT"] != 90 {
		t.Fatalf("STATUS values: %#v %v", values, err)
	}
	_, search, err := readReply(r)
	if err != nil {
		t.Fatal(err)
	}
	numbers, err := (Response{Untagged: []Reply{search}}).Search()
	if err != nil || len(numbers) != 2 || numbers[0] != 5 || numbers[1] != 8 {
		t.Fatalf("SEARCH numbers: %#v %v", numbers, err)
	}
}
