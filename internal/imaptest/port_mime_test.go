package imaptest

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestPortMIMEExpectationsAreValidProtocolData(t *testing.T) {
	groups := 0
	for _, fixture := range portMIMEFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			messages, err := portFixture(fixture.name)
			if err != nil || len(messages) != 1 {
				t.Fatalf("fixture: messages=%d err=%v", len(messages), err)
			}
			for _, step := range fixture.steps {
				groups++
				reader := bufio.NewReader(strings.NewReader(step.reply))
				tag, reply, err := readReply(reader)
				if err != nil || tag != "*" {
					t.Fatalf("%s expectation: tag=%q err=%v", step.command, tag, err)
				}
				fetches, err := (Response{Untagged: []Reply{reply}}).Fetches()
				if err != nil || len(fetches) != 1 {
					t.Fatalf("%s expectation: fetches=%d err=%v", step.command, len(fetches), err)
				}
				if reader.Buffered() != 0 {
					t.Fatalf("%s expectation contains a second unparsed reply", step.command)
				}
				for _, key := range []string{"BODY[]", "BINARY[]"} {
					if value, ok := fetches[0].Attrs[key]; ok && !bytes.Equal([]byte(value.Text), messages[0]) {
						t.Errorf("%s full-message expectation differs from APPEND fixture: got %d bytes, fixture %d", step.command, len(value.Text), len(messages[0]))
					}
				}
			}
		})
	}
	if groups != 72 {
		t.Fatalf("native MIME table lost upstream command groups: got %d, want 72", groups)
	}
}

func TestPortMIMEBinaryPartialsUseDecodedOctetOffsets(t *testing.T) {
	for _, fixture := range portMIMEFixtures {
		if fixture.name != "fetch-binary-mime-base64" && fixture.name != "fetch-binary-mime-qp" {
			continue
		}
		full := map[string]string{}
		for _, step := range fixture.steps {
			_, reply, err := readReply(bufio.NewReader(strings.NewReader(step.reply)))
			if err != nil {
				t.Fatal(err)
			}
			fetches, err := (Response{Untagged: []Reply{reply}}).Fetches()
			if err != nil {
				t.Fatal(err)
			}
			for name, value := range fetches[0].Attrs {
				if strings.HasPrefix(name, "BINARY[") && !strings.Contains(name, "<") {
					full[name] = value.Text
				}
			}
		}
		for _, step := range fixture.steps {
			if !strings.Contains(step.command, "<") {
				continue
			}
			_, reply, err := readReply(bufio.NewReader(strings.NewReader(step.reply)))
			if err != nil {
				t.Fatal(err)
			}
			fetches, err := (Response{Untagged: []Reply{reply}}).Fetches()
			if err != nil {
				t.Fatal(err)
			}
			for key, value := range fetches[0].Attrs {
				base, _, ok := strings.Cut(key, "<")
				if !ok {
					continue
				}
				var offset, count int
				if _, err := portMIMEScanPartial(step.command, &offset, &count); err != nil {
					t.Fatal(err)
				}
				body := full[base]
				start := min(offset, len(body))
				end := min(start+count, len(body))
				if value.Text != body[start:end] {
					t.Fatalf("%s: partial=%q, decoded slice=%q", step.command, value.Text, body[start:end])
				}
			}
		}
	}
}

func portMIMEScanPartial(command string, offset, count *int) (int, error) {
	_, tail, _ := strings.Cut(command, "<")
	return fmt.Sscanf(tail, "%d.%d>", offset, count)
}

func TestPortMIMEHeaderFilteringPreservesOctetsAndDuplicates(t *testing.T) {
	header := "From: Sender <sender@example.test>\r\nX-Folded: one\r\n two\r\nSubject: Mixed Case\r\n\r\n"
	if got := portMIMEFilteredHeader(header, []string{"FROM", "FROM", "SUBJECT"}, nil); got != "From: Sender <sender@example.test>\r\nSubject: Mixed Case\r\n\r\n" {
		t.Fatalf("field filtering=%q", got)
	}
	if got := portMIMEFilteredHeader(header, []string{"X-FOLDED"}, nil); got != "X-Folded: one\r\n two\r\n\r\n" {
		t.Fatalf("folded field=%q", got)
	}
	if got := portMIMEFilteredHeader(header, []string{"ABSENT"}, nil); got != "\r\n" {
		t.Fatalf("absent field must retain a blank header terminator: %q", got)
	}
}

func TestPortMIMEByteAssertionsAcceptLiteralRepresentationButRejectChangedBytes(t *testing.T) {
	want := Fetch{Seq: 1, Attrs: map[string]Value{"BODY[]": {Text: "MiXeD\x00\xe4\r\n", IsLiteral: true}}}
	got := Fetch{Seq: 1, Attrs: map[string]Value{"BODY[]": {Text: "MiXeD\x00\xe4\r\n"}, "FLAGS": {IsList: true}}}
	if err := portMIMEFetchEqual(got, want); err != nil {
		t.Fatal(err)
	}
	got.Attrs["BODY[]"] = Value{Text: "mixed\x00\xe4\r\n"}
	if err := portMIMEFetchEqual(got, want); err == nil {
		t.Fatal("accepted body case normalization")
	}
	delete(got.Attrs, "BODY[]")
	if err := portMIMEFetchEqual(got, want); err == nil {
		t.Fatal("FLAGS-only response satisfied BODY request")
	}
}

func TestPortMIMEEnvelopeAllowsIgnoredSourceRouteButRequiresMailbox(t *testing.T) {
	parse := func(raw string) Value {
		t.Helper()
		parser := valueParser{data: []byte(raw)}
		value, err := parser.value(0)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	want := portMIMEEnvelopes[5]
	for _, tc := range []struct {
		name, actual string
		match        bool
	}{
		{"original route", want, true},
		{"ignored routes", strings.ReplaceAll(want, `"@route"`, "NIL"), true},
		{"one ignored route", strings.Replace(want, `"@route"`, "NIL", 1), true},
		{"different route", strings.ReplaceAll(want, `"@route"`, `"@other"`), false},
		{"different mailbox", strings.ReplaceAll(want, `"user"`, `"other"`), false},
		{"different host", strings.ReplaceAll(want, `"domain"`, `"other"`), false},
		{"missing address", strings.Replace(want, `((NIL "@route" "user" "domain"))`, "NIL", 1), false},
		{"all addresses lost", `("Thu, 15 Feb 2007 01:02:03 +0200" NIL NIL NIL NIL NIL NIL NIL NIL NIL)`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if match := portMIMEEnvelopeEqual(parse(tc.actual), parse(want)); match != tc.match {
				t.Fatalf("ENVELOPE comparison=%t, want %t", match, tc.match)
			}
		})
	}
	for _, envelope := range portMIMEEnvelopes {
		if !portMIMEEnvelopeEqual(parse(envelope), parse(envelope)) {
			t.Fatalf("unchanged envelope no longer matches: %s", envelope)
		}
	}
}

func TestPortMIMEFetchUsesSemanticHeaderKeys(t *testing.T) {
	c := coreReplyClient(t, "* 1 FETCH (FLAGS () BODY[HEADER.FIELDS (\"Subject\")] {18}\r\nSubject: Value\r\n\r\n)\r\n")
	step := portMIMEFetchStep{command: "FETCH 1 BODY.PEEK[HEADER.FIELDS (SUBJECT)]", reply: "* 1 FETCH (BODY[HEADER.FIELDS (SUBJECT)] {18}\r\nSubject: Value\r\n\r\n)\r\n"}
	if err := portMIMEFetchStepCheck(c, step); err != nil {
		t.Fatal(err)
	}
}

func TestPortMIMEFlagsAllowServerKeywordsButRequireSystemState(t *testing.T) {
	for _, tc := range []struct {
		flags     string
		wantError bool
	}{
		{`($hasnoattachment \Recent)`, false},
		{`(\Draft)`, true},
		{`NIL`, true},
	} {
		c := coreReplyClient(t, "* 1 FETCH (FLAGS "+tc.flags+")\r\n")
		if err := portMIMESeen(c, 1, false); (err != nil) != tc.wantError {
			t.Fatalf("FLAGS %s: err=%v wantError=%t", tc.flags, err, tc.wantError)
		}
	}
}

func TestPortMIMEBodystructureHandlesRangeFetch(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		wantError  bool
	}{
		{"valid", `(("text" "X-myown" ("charset" "US-ASCII") NIL NIL "7bit" 7 1) "mixed")`, false},
		{"illegal-part-extension", `(("text" "X-myown" ("charset" "US-ASCII") NIL NIL "7bit" 7 1 NIL) "mixed")`, true},
		{"illegal-multipart-extension", `(("text" "X-myown" ("charset" "US-ASCII") NIL NIL "7bit" 7 1) "mixed" NIL)`, true},
		{"wrong-size", `(("text" "X-myown" ("charset" "US-ASCII") NIL NIL "7bit" 8 1) "mixed")`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := coreReplyClient(t, "* 1 FETCH (BODY "+tc.body+")\r\n")
			err := portMIMEFetchBodystructure(c)
			if (err != nil) != tc.wantError {
				t.Fatalf("BODY range assertion error=%v, wantError=%t", err, tc.wantError)
			}
		})
	}
}

func TestPortMIMEBinaryFixtureLabelsMixedOctetsAsApplicationData(t *testing.T) {
	messages, err := portFixture("fetch-binary-mime-base64")
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), messages[0]...)
	adapted, err := portMIMEBinaryOctetFixture(messages[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, messages[0]) {
		t.Fatal("binary fixture adaptation mutated immutable source")
	}
	if bytes.Count(adapted, []byte("Content-Type: application/octet-stream")) != 1 || bytes.Count(adapted, []byte("Content-Type: text/x-myown")) != 4 {
		t.Fatal("adaptation changed more than the fifth MIME type")
	}
	_, lastPart, _ := bytes.Cut(adapted, []byte("Content-Type: application/octet-stream\r\n"))
	_, encoded, _ := bytes.Cut(lastPart, []byte("\r\n\r\n"))
	encoded, _, _ = bytes.Cut(encoded, []byte("\r\n--foo bar"))
	decoded, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "abcdefg\rhijkl\r\nmno\npqrstuvqxyz" {
		t.Fatalf("binary fixture payload changed: %q", decoded)
	}
}
