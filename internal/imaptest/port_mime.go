package imaptest

import (
	"bufio"
	"bytes"
	"fmt"
	"slices"
	"strings"
)

// The literal expectations below are adapted from dovecot/imaptest at the
// pinned revision documented in testdata/imaptest. They are native Go data:
// the runner does not load or interpret upstream test scripts.
func portMIMECases() []Case {
	cases := []Case{
		portCase("append-binary", "Binary APPEND preserves octets through BINARY and emits a legal BODY representation", "https://www.rfc-editor.org/rfc/rfc3516.html#section-4.3", []string{"BINARY"}, portMIMEAppendBinary),
		portCase("fetch-body", "RFC822 aliases, Seen side effects, partial octets, and header field selection", coreRFC+"6.4.5", nil, portMIMEBody),
		portCase("fetch-bodystructure", "BODY describes the multipart fixture's text subtype, charset, size and line count", coreRFC+"7.4.2", nil, portMIMEBodystructure),
		portCase("fetch-envelope", "ENVELOPE fields, address groups, defaults and source routes", coreRFC+"7.4.2", nil, portMIMEEnvelope),
		portCase("nil", "NIL remains a valid SEARCH argument, mailbox pattern and keyword", coreRFC+"4.2", nil, portMIMENil),
	}
	for _, fixture := range portMIMEFixtures {
		fixture := fixture
		requires := []string(nil)
		rfc := coreRFC + "6.4.5"
		if strings.HasPrefix(fixture.name, "fetch-binary-") {
			requires = []string{"BINARY"}
			rfc = "https://www.rfc-editor.org/rfc/rfc3516.html#section-4.2"
		}
		cases = append(cases, portCase(fixture.name, "Exact MIME section and decoded-byte expectations from the upstream fixture", rfc, requires, func(s *Session) error {
			if err := portMIMEPrepare(s, fixture.name); err != nil {
				return err
			}
			for _, step := range fixture.steps {
				if err := portMIMEFetchStepCheck(s.Client, step); err != nil {
					return fmt.Errorf("%s: %w", step.command, err)
				}
			}
			return nil
		}))
	}
	return cases
}

func portMIMEPrepare(s *Session, fixture string) error {
	if fixture != "fetch-binary-mime-base64" {
		_, _, err := portMailbox(s, fixture, -1, true)
		return err
	}
	messages, dates, err := portReadFixture(fixture)
	if err != nil {
		return err
	}
	box, err := s.NewMailbox("messages")
	if err != nil {
		return err
	}
	for i, message := range messages {
		adapted, err := portMIMEBinaryOctetFixture(message)
		if err != nil {
			return err
		}
		if _, err := s.Client.Append(box, nil, dates[i], adapted); err != nil {
			return err
		}
	}
	_, err = s.Client.OK("SELECT " + Quote(box))
	return err
}

func portMIMEBinaryOctetFixture(message []byte) ([]byte, error) {
	// Upstream's fifth base64 part deliberately decodes mixed CR/LF octets
	// but labels them text/x-myown. RFC 3516 section 6 requires line-oriented
	// textual sections to use CRLF, so label this copied part octet-stream.
	// The vendored source fixture stays unchanged; decoding and offset checks
	// now have unambiguous binary semantics instead of a server convention.
	textType := []byte("Content-Type: text/x-myown; charset=us-ascii\r\n")
	if bytes.Count(message, textType) != 5 {
		return nil, fmt.Errorf("base64 fixture lacks its five expected MIME parts")
	}
	start := bytes.LastIndex(message, textType)
	result := append([]byte(nil), message[:start]...)
	result = append(result, []byte("Content-Type: application/octet-stream\r\n")...)
	result = append(result, message[start+len(textType):]...)
	return result, nil
}

type portMIMEFetchStep struct {
	command string
	reply   string // a fixed RFC response, including exact literal bytes
}

func portMIMEFetchStepCheck(c *Client, step portMIMEFetchStep) error {
	_, expected, err := readReply(bufio.NewReader(strings.NewReader(step.reply)))
	if err != nil {
		return fmt.Errorf("invalid native MIME expectation: %w", err)
	}
	expectedFetches, err := (Response{Untagged: []Reply{expected}}).Fetches()
	if err != nil || len(expectedFetches) != 1 {
		return fmt.Errorf("native MIME expectation does not contain one FETCH: %v", err)
	}
	actual, err := coreSingleFetch(c, step.command)
	if err != nil {
		return err
	}
	return portMIMEFetchEqual(actual, expectedFetches[0])
}

func portMIMEFetchEqual(actual, expected Fetch) error {
	if err := Check(actual.Seq == expected.Seq, "FETCH sequence=%d, want %d", actual.Seq, expected.Seq); err != nil {
		return err
	}
	names := make([]string, 0, len(expected.Attrs))
	for name := range expected.Attrs {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		want := expected.Attrs[name]
		got, err := coreAttribute(actual, name)
		if err != nil {
			return err
		}
		if strings.HasPrefix(name, "BINARY.SIZE[") {
			gotSize, gotErr := got.Uint()
			wantSize, wantErr := want.Uint()
			if gotErr != nil || wantErr != nil {
				return fmt.Errorf("invalid %s size", name)
			}
			if err := Check(gotSize == wantSize, "%s=%d, want %d", name, gotSize, wantSize); err != nil {
				return err
			}
		} else if err := Check(portMIMEValueEqual(got, want), "%s differs: got %q, want %q", name, got.String(), want.String()); err != nil {
			return err
		}
	}
	return nil
}

// Quoted strings and literals are interchangeable on the wire. Their bytes,
// including trailing CRLF and embedded NUL, are compared without normalization.
func portMIMEValueEqual(got, want Value) bool {
	if got.IsNil != want.IsNil || got.IsList != want.IsList {
		return false
	}
	if want.IsList {
		if len(got.List) != len(want.List) {
			return false
		}
		for i := range want.List {
			if !portMIMEValueEqual(got.List[i], want.List[i]) {
				return false
			}
		}
		return true
	}
	return got.IsNil || got.Text == want.Text
}

func portMIMEAppendBinary(s *Session) error {
	box, err := s.NewMailbox("binary")
	if err != nil {
		return err
	}
	payload := []byte{0, '-', 0xe4, '\n', '\r', '\n', '\n'}
	message := append([]byte("From: user@domain.org\r\nDate: Sat, 24 Mar 2007 23:00:00 +0200\r\nMIME-Version: 1.0\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n"), payload...)
	if response, err := s.Client.AppendBinary(box, nil, "", message); err != nil {
		if response.Status == "NO" && response.Code("UNKNOWN-CTE") != nil {
			return Skip("mailbox rejects binary APPEND with RFC 3516 UNKNOWN-CTE")
		}
		return err
	}
	if _, err := coreSelect(s.Client, box); err != nil {
		return err
	}
	f, err := coreSingleFetch(s.Client, "FETCH 1 BODY.PEEK[1]")
	if err != nil {
		return err
	}
	body, err := coreAttribute(f, "BODY[1]")
	if err != nil {
		return err
	}
	// BINARY APPEND may recode binary content for ordinary BODY retrieval, but
	// it must not expose NUL through the non-binary IMAP string production.
	if err := Check(!strings.ContainsRune(body.Text, 0), "BODY[1] after binary APPEND contains NUL"); err != nil {
		return err
	}
	f, err = coreSingleFetch(s.Client, "FETCH 1 (BINARY.SIZE[1] BINARY.PEEK[1])")
	if err != nil {
		return err
	}
	decoded, err := coreAttribute(f, "BINARY[1]")
	if err != nil {
		return err
	}
	sizeValue, err := coreAttribute(f, "BINARY.SIZE[1]")
	if err != nil {
		return err
	}
	size, err := sizeValue.Uint()
	if err != nil {
		return err
	}
	return Check(bytes.Equal([]byte(decoded.Text), payload) && size == uint64(len(payload)), "binary APPEND changed decoded octets or size: got %q/%d, want %q/%d", decoded.Text, size, payload, len(payload))
}

func portMIMEBody(s *Session) error {
	_, messages, err := portMailbox(s, "fetch-body", -1, true)
	if err != nil {
		return err
	}
	if len(messages) != 4 {
		return fmt.Errorf("fetch-body fixture has %d messages, want 4", len(messages))
	}
	headers := make([]string, 4)
	bodies := make([]string, 4)
	for i, message := range messages {
		header, body, ok := bytes.Cut(message, []byte("\r\n\r\n"))
		if !ok {
			return fmt.Errorf("fetch-body fixture %d has no header terminator", i+1)
		}
		headers[i] = string(header) + "\r\n\r\n"
		bodies[i] = string(body)
	}
	for _, step := range []struct {
		command, attribute, want string
		seen                     *bool
	}{
		{"FETCH 1 RFC822.HEADER", "RFC822.HEADER", headers[0], nil},
		{"FETCH 1 BODY.PEEK[HEADER]", "BODY[HEADER]", headers[0], nil},
		{"FETCH 1 (FLAGS BODY.PEEK[TEXT])", "BODY[TEXT]", bodies[0], portMIMEBool(false)},
		{"FETCH 1 RFC822.TEXT", "RFC822.TEXT", bodies[0], portMIMEBool(true)},
		{"FETCH 2 (FLAGS BODY.PEEK[])", "BODY[]", string(messages[1]), portMIMEBool(false)},
		{"FETCH 2 RFC822", "RFC822", string(messages[1]), portMIMEBool(true)},
		{"FETCH 3 BODY[]", "BODY[]", string(messages[2]), portMIMEBool(true)},
		{"FETCH 4 BODY[HEADER]", "BODY[HEADER]", headers[3], portMIMEBool(true)},
	} {
		if err := portMIMETextFetch(s.Client, step.command, step.attribute, step.want); err != nil {
			return err
		}
		if step.seen != nil {
			var sequence uint64
			fmt.Sscanf(step.command, "FETCH %d", &sequence)
			if err := portMIMESeen(s.Client, sequence, *step.seen); err != nil {
				return err
			}
		}
	}
	for _, partial := range []struct{ sequence, offset, count int }{{2, 0, 3}, {2, 3, 3}, {3, 0, 1}, {3, 5, 1}, {3, 5, 2}, {3, 5, 3}, {3, 6, 1}, {3, 6, 2}, {3, 7, 1}} {
		body := bodies[partial.sequence-1]
		start := min(partial.offset, len(body))
		end := min(start+partial.count, len(body))
		if err := portMIMETextFetch(s.Client, fmt.Sprintf("FETCH %d BODY.PEEK[TEXT]<%d.%d>", partial.sequence, partial.offset, partial.count), fmt.Sprintf("BODY[TEXT]<%d>", partial.offset), body[start:end]); err != nil {
			return err
		}
	}
	for _, fields := range []struct {
		command, attribute string
		wanted, excluded   []string
	}{
		{"FETCH 1 BODY.PEEK[HEADER.FIELDS (FROM)]", "BODY[HEADER.FIELDS (FROM)]", []string{"FROM"}, nil},
		{"FETCH 1 (BODY.PEEK[HEADER.FIELDS (FROM)])", "BODY[HEADER.FIELDS (FROM)]", []string{"FROM"}, nil},
		{"FETCH 1 (BODY.PEEK[HEADER.FIELDS (FROM FROM)])", "BODY[HEADER.FIELDS (FROM FROM)]", []string{"FROM"}, nil},
		{"FETCH 1 BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)]", "BODY[HEADER.FIELDS (FROM SUBJECT)]", []string{"FROM", "SUBJECT"}, nil},
		{"FETCH 1 BODY.PEEK[HEADER.FIELDS.NOT (DATE)]", "BODY[HEADER.FIELDS.NOT (DATE)]", nil, []string{"DATE"}},
		{"FETCH 1 BODY.PEEK[HEADER.FIELDS.NOT (DATE DATE)]", "BODY[HEADER.FIELDS.NOT (DATE DATE)]", nil, []string{"DATE"}},
		{"FETCH 1 BODY.PEEK[HEADER.FIELDS (XYZ)]", "BODY[HEADER.FIELDS (XYZ)]", []string{"XYZ"}, nil},
	} {
		want := portMIMEFilteredHeader(headers[0], fields.wanted, fields.excluded)
		if err := portMIMETextFetch(s.Client, fields.command, fields.attribute, want); err != nil {
			return err
		}
	}
	return nil
}

func portMIMEBool(value bool) *bool { return &value }

func portMIMETextFetch(c *Client, command, attribute, want string) error {
	f, err := coreSingleFetch(c, command)
	if err != nil {
		return err
	}
	value, err := coreAttribute(f, attribute)
	if err != nil {
		return err
	}
	return Check(!value.IsNil && !value.IsList && value.Text == want, "%s: %s got %q, want %q", command, attribute, value.Text, want)
}

func portMIMESeen(c *Client, sequence uint64, seen bool) error {
	f, err := coreSingleFetch(c, fmt.Sprintf("FETCH %d FLAGS", sequence))
	if err != nil {
		return err
	}
	flags, err := coreAttribute(f, "FLAGS")
	if err != nil {
		return err
	}
	if err := Check(flags.IsList, "FLAGS for sequence %d is not a flag list", sequence); err != nil {
		return err
	}
	if err := Check(coreHasFlag(flags, "\\Seen") == seen, "sequence %d Seen=%t, want %t", sequence, coreHasFlag(flags, "\\Seen"), seen); err != nil {
		return err
	}
	for _, flag := range []string{"\\Answered", "\\Flagged", "\\Deleted", "\\Draft"} {
		if err := Check(!coreHasFlag(flags, flag), "sequence %d acquired unexpected system flag %s", sequence, flag); err != nil {
			return err
		}
	}
	return nil
}

func portMIMEFilteredHeader(header string, wanted, excluded []string) string {
	var result strings.Builder
	include := false
	for _, line := range strings.Split(strings.TrimSuffix(header, "\r\n\r\n"), "\r\n") {
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			name, _, _ := strings.Cut(line, ":")
			name = strings.ToUpper(name)
			include = (wanted == nil || slices.Contains(wanted, name)) && !slices.Contains(excluded, name)
		}
		if include {
			result.WriteString(line + "\r\n")
		}
	}
	result.WriteString("\r\n")
	return result.String()
}

func portMIMEBodystructure(s *Session) error {
	if _, _, err := portMailbox(s, "fetch-bodystructure", -1, true); err != nil {
		return err
	}
	return portMIMEFetchBodystructure(s.Client)
}

func portMIMEFetchBodystructure(c *Client) error {
	fetches, err := coreFetch(c, "FETCH 1:* BODY")
	if err != nil {
		return err
	}
	var body Value
	found := false
	for _, f := range fetches {
		if f.Seq == 1 {
			if v, ok := f.Attrs["BODY"]; ok {
				body, found = v, true
			}
		}
	}
	if err := Check(found, "FETCH 1:* BODY omitted BODY for sequence 1"); err != nil {
		return err
	}
	// BODY is the non-extended representation. RFC 3501 section 7.4.2 only
	// permits optional extension data on BODYSTRUCTURE, never on BODY.
	if err := Check(body.IsList && len(body.List) == 2 && body.List[0].IsList && strings.EqualFold(body.List[1].Text, "MIXED"), "BODY does not describe one non-extended multipart/mixed part"); err != nil {
		return err
	}
	part := body.List[0]
	if err := Check(part.IsList && len(part.List) == 8, "non-extended BODY text part must contain exactly eight fields"); err != nil {
		return err
	}
	if err := Check(strings.EqualFold(part.List[0].Text, "TEXT") && strings.EqualFold(part.List[1].Text, "x-MYOWN") && strings.EqualFold(part.List[5].Text, "7BIT") && part.List[3].IsNil && part.List[4].IsNil, "BODY text type, encoding, content-id or description differ"); err != nil {
		return err
	}
	params := part.List[2]
	if err := Check(params.IsList && len(params.List)%2 == 0, "BODY content parameters are malformed"); err != nil {
		return err
	}
	charset := ""
	for i := 0; i < len(params.List); i += 2 {
		if strings.EqualFold(params.List[i].Text, "CHARSET") {
			charset = params.List[i+1].Text
		}
	}
	if err := Check(strings.EqualFold(charset, "us-ascii"), "BODY charset=%q, want us-ascii", charset); err != nil {
		return err
	}
	size, err := part.List[6].Uint()
	if err != nil {
		return err
	}
	lines, err := part.List[7].Uint()
	if err != nil {
		return err
	}
	return Check(size == 7 && lines == 1, "BODY text size/lines=%d/%d, want 7/1", size, lines)
}

func portMIMEEnvelope(s *Session) error {
	if _, _, err := portMailbox(s, "fetch-envelope", -1, true); err != nil {
		return err
	}
	fetches, err := coreFetch(s.Client, "FETCH 1:* ENVELOPE")
	if err != nil {
		return err
	}
	for i, want := range portMIMEEnvelopes {
		p := valueParser{data: []byte(want)}
		expected, err := p.value(0)
		if err != nil {
			return fmt.Errorf("invalid native envelope expectation: %w", err)
		}
		found := false
		for _, f := range fetches {
			if f.Seq == uint64(i+1) {
				got, err := coreAttribute(f, "ENVELOPE")
				if err != nil {
					return err
				}
				if err := Check(portMIMEEnvelopeEqual(got, expected), "ENVELOPE for sequence %d differs: got %s, want %s", i+1, got.String(), expected.String()); err != nil {
					return err
				}
				found = true
				break
			}
		}
		if err := Check(found, "FETCH omitted ENVELOPE for sequence %d", i+1); err != nil {
			return err
		}
	}
	return nil
}

// RFC 5322 section 4.4 recommends ignoring obsolete source routes. Accept NIL
// for an expected addr-adl, while still requiring every address and its mailbox,
// host, display name, and position in the envelope.
func portMIMEEnvelopeEqual(got, want Value) bool {
	if !got.IsList || !want.IsList || len(got.List) != 10 || len(want.List) != 10 {
		return false
	}
	for field, expected := range want.List {
		actual := got.List[field]
		if field < 2 || field > 7 || expected.IsNil {
			if !portMIMEValueEqual(actual, expected) {
				return false
			}
			continue
		}
		if !actual.IsList || !expected.IsList || len(actual.List) != len(expected.List) {
			return false
		}
		for i, address := range expected.List {
			peerAddress := actual.List[i]
			if !address.IsList || !peerAddress.IsList || len(address.List) != 4 || len(peerAddress.List) != 4 {
				return false
			}
			for part, value := range address.List {
				if part == 1 && !value.IsList && !value.IsNil && strings.HasPrefix(value.Text, "@") && peerAddress.List[part].IsNil {
					continue
				}
				if !portMIMEValueEqual(peerAddress.List[part], value) {
					return false
				}
			}
		}
	}
	return true
}

func portMIMENil(s *Session) error {
	box, _, err := portIndexedMailbox(s, "nil", 1, true)
	if err != nil {
		return err
	}
	// Quote the readiness term so the later unquoted NIL assertion still
	// independently checks atom handling after the index is available.
	if err := waitForIndexing(s, "BODY "+Quote("nil"), 1); err != nil {
		return err
	}
	if err := coreSearch(s.Client, "SUBJECT NIL", 1); err != nil {
		return err
	}
	if err := coreSearch(s.Client, "BODY nil", 1); err != nil {
		return err
	}
	if _, err := s.Client.OK("LIST \"\" NIL"); err != nil {
		return err
	}
	selected, err := coreSelect(s.Client, box)
	if err != nil {
		return err
	}
	flags := selected.Code("PERMANENTFLAGS")
	if len(flags) != 1 || (!coreHasFlag(flags[0], "\\*") && !coreHasFlag(flags[0], "NIL")) {
		return Skip("PERMANENTFLAGS does not permit the NIL keyword")
	}
	if _, err := s.Client.OK("STORE 1 +FLAGS NIL"); err != nil {
		return err
	}
	f, err := coreSingleFetch(s.Client, "FETCH 1 FLAGS")
	if err != nil {
		return err
	}
	return Check(coreHasFlag(f.Attrs["FLAGS"], "NIL"), "NIL keyword did not round-trip through STORE/FETCH")
}

var portMIMEFixtures = []struct {
	name  string
	steps []portMIMEFetchStep
}{
	{name: "fetch-binary-mime", steps: []portMIMEFetchStep{
		{command: "fetch 1 (binary.peek[])", reply: "* 1 fetch (binary[] {602}\r\nFrom: user@domain.org\r\nDate: Sat, 24 Mar 2007 23:00:00 +0200\r\nMime-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"foo\r\n bar\"\r\n\r\nRoot MIME prologue\r\n\r\n--foo bar\r\nContent-Type: text/x-myown; charset=us-ascii\r\n\r\nhello\r\n\r\n--foo bar\r\nContent-Type: message/rfc822\r\n\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\nContent-Type: multipart/alternative; boundary=\"sub1\"\r\n\r\nSub MIME prologue\r\n--sub1\r\nContent-Type: text/html\r\n\r\n<p>Hello world</p>\r\n\r\n--sub1\r\nContent-Type: text/plain\r\n\r\nHello another world\r\n\r\n--sub1--\r\nSub MIME epilogue\r\n\r\n--foo bar--\r\nRoot MIME epilogue\r\n)\r\n"},
		{command: "fetch 1 (binary.size[])", reply: "* 1 fetch (binary.size[] 602)\r\n"},
		{command: "fetch 1 (binary.size[1])", reply: "* 1 fetch (binary.size[1] 7)\r\n"},
		{command: "fetch 1 (binary.peek[1])", reply: "* 1 fetch (binary[1] {7}\r\nhello\r\n)\r\n"},
		{command: "fetch 1 (binary.peek[2])", reply: "* 1 fetch (binary[2] {298}\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\nContent-Type: multipart/alternative; boundary=\"sub1\"\r\n\r\nSub MIME prologue\r\n--sub1\r\nContent-Type: text/html\r\n\r\n<p>Hello world</p>\r\n\r\n--sub1\r\nContent-Type: text/plain\r\n\r\nHello another world\r\n\r\n--sub1--\r\nSub MIME epilogue\r\n)\r\n"},
		{command: "fetch 1 (binary.size[2])", reply: "* 1 fetch (binary.size[2] 298)\r\n"},
		{command: "fetch 1 (binary.size[2.1])", reply: "* 1 fetch (binary.size[2.1] 20)\r\n"},
		{command: "fetch 1 (binary.peek[2.1])", reply: "* 1 fetch (binary[2.1] {20}\r\n<p>Hello world</p>\r\n)\r\n"},
		{command: "fetch 1 (binary.peek[2.2])", reply: "* 1 fetch (binary[2.2] {21}\r\nHello another world\r\n)\r\n"},
		{command: "fetch 1 (binary.size[2.2])", reply: "* 1 fetch (binary.size[2.2] 21)\r\n"},
	}},
	{name: "fetch-binary-mime-base64", steps: []portMIMEFetchStep{
		{command: "fetch 1 (binary.size[1] binary.size[5])", reply: "* 1 fetch (binary.size[1] 11 binary.size[5] 30)\r\n"},
		{command: "fetch 1 (binary.peek[1] binary.peek[2] binary.peek[3] binary.peek[4] binary.peek[5])", reply: "* 1 fetch (binary[1] {11}\r\nhello world binary[2] {11}\r\nhello world binary[3] {16}\r\nhello to you too binary[4] {18}\r\nhello to everyone! binary[5] ~{30}\r\nabcdefg\rhijkl\r\nmno\npqrstuvqxyz)\r\n"},
		{command: "fetch 1 (binary.size[1] binary.peek[1])", reply: "* 1 fetch (binary.size[1] 11 binary[1] {11}\r\nhello world)\r\n"},
		{command: "fetch 1 (binary.size[3] binary.peek[2])", reply: "* 1 fetch (binary.size[3] 16 binary[2] {11}\r\nhello world)\r\n"},
		{command: "fetch 1 (binary.size[2] binary.size[3] binary.size[4])", reply: "* 1 fetch (binary.size[2] 11 binary.size[3] 16 binary.size[4] 18)\r\n"},
		{command: "fetch 1 (binary.peek[5]<0.7>)", reply: "* 1 fetch (binary[5]<0> ~{7}\r\nabcdefg)\r\n"},
		{command: "fetch 1 (binary.peek[5]<0.8>)", reply: "* 1 fetch (binary[5]<0> ~{8}\r\nabcdefg\r)\r\n"},
		{command: "fetch 1 (binary.peek[5]<0.10>)", reply: "* 1 fetch (binary[5]<0> ~{10}\r\nabcdefg\rhi)\r\n"},
		{command: "fetch 1 (binary.peek[5]<10.10>)", reply: "* 1 fetch (binary[5]<10> ~{10}\r\njkl\r\nmno\np)\r\n"},
		{command: "fetch 1 (binary.peek[5]<5.10>)", reply: "* 1 fetch (binary[5]<5> ~{10}\r\nfg\rhijkl\r\n)\r\n"},
		{command: "fetch 1 (binary.peek[5]<15.100>)", reply: "* 1 fetch (binary[5]<15> ~{15}\r\nmno\npqrstuvqxyz)\r\n"},
	}},
	{name: "fetch-binary-mime-qp", steps: []portMIMEFetchStep{
		{command: "fetch 1 (binary.size[1])", reply: "* 1 fetch (binary.size[1] 65)\r\n"},
		{command: "fetch 1 (binary.peek[1])", reply: "* 1 fetch (binary[1] {65}\r\nhello\r\nbar\r\nfoo\tbar\r\nfoo\t \tb\r\nfoo bar\r\nfoo b\r\nfoo\r\nbar\r\nfoo_bar\r\n)\r\n"},
		{command: "fetch 1 (binary.peek[1]<0.10>)", reply: "* 1 fetch (binary[1]<0> {10}\r\nhello\r\nbar)\r\n"},
		{command: "fetch 1 (binary.peek[1]<10.10>)", reply: "* 1 fetch (binary[1]<10> ~{10}\r\n\r\nfoo\tbar\r)\r\n"},
		{command: "fetch 1 (binary.peek[1]<20.10>)", reply: "* 1 fetch (binary[1]<20> ~{10}\r\n\nfoo\t \tb\r\n)\r\n"},
		{command: "fetch 1 (binary.peek[1]<15.10>)", reply: "* 1 fetch (binary[1]<15> ~{10}\r\n\tbar\r\nfoo\t)\r\n"},
		{command: "fetch 1 (binary.peek[1]<40.100>)", reply: "* 1 fetch (binary[1]<40> {25}\r\noo b\r\nfoo\r\nbar\r\nfoo_bar\r\n)\r\n"},
	}},
	{name: "fetch-body-message-rfc822", steps: []portMIMEFetchStep{
		{command: "fetch 1 (body.peek[])", reply: "* 1 fetch (body[] {206}\r\nFrom: user@domain.org\r\nDate: Sat, 24 Mar 2007 23:00:00 +0200\r\nMime-Version: 1.0\r\nContent-Type: message/rfc822\r\n\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\n\r\nHello world\r\n)\r\n"},
		{command: "fetch 1 (body.peek[text])", reply: "* 1 fetch (body[text] {93}\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\n\r\nHello world\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1])", reply: "* 1 fetch (body[1] {93}\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\n\r\nHello world\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.1])", reply: "* 1 fetch (body[1.1] {13}\r\nHello world\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.header])", reply: "* 1 fetch (body[1.header] {80}\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.header.fields (from subject X-foo)])", reply: "* 1 fetch (body[1.header.fields (from subject X-foo)] {41}\r\nFrom: sub@domain.org\r\nSubject: submsg\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.header.fields.not (from subject X-foo)])", reply: "* 1 fetch (body[1.header.fields.not (from subject X-foo)] {41}\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.text])", reply: "* 1 fetch (body[1.text] {13}\r\nHello world\r\n)\r\n"},
	}},
	{name: "fetch-body-message-rfc822-mime", steps: []portMIMEFetchStep{
		{command: "fetch 1 (body.peek[])", reply: "* 1 fetch (body[] {409}\r\nFrom: user@domain.org\r\nDate: Sat, 24 Mar 2007 23:00:00 +0200\r\nMime-Version: 1.0\r\nContent-Type: message/rfc822\r\n\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\nContent-Type: multipart/digest; boundary=\"foo\"\r\n\r\nprologue\r\n\r\n--foo \r\n\r\nFrom: m1@example.com\r\nSubject: m1\r\n\r\nm1 body\r\n\r\n--foo \r\nX-Mime: m2 header\r\n\r\nFrom: m2@example.com\r\nSubject: m2\r\n\r\nm2 body\r\n\r\n--foo--\r\n\r\nepilogue\r\n)\r\n"},
		{command: "fetch 1 (body.peek[text])", reply: "* 1 fetch (body[text] {296}\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\nContent-Type: multipart/digest; boundary=\"foo\"\r\n\r\nprologue\r\n\r\n--foo \r\n\r\nFrom: m1@example.com\r\nSubject: m1\r\n\r\nm1 body\r\n\r\n--foo \r\nX-Mime: m2 header\r\n\r\nFrom: m2@example.com\r\nSubject: m2\r\n\r\nm2 body\r\n\r\n--foo--\r\n\r\nepilogue\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1])", reply: "* 1 fetch (body[1] {296}\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\nContent-Type: multipart/digest; boundary=\"foo\"\r\n\r\nprologue\r\n\r\n--foo \r\n\r\nFrom: m1@example.com\r\nSubject: m1\r\n\r\nm1 body\r\n\r\n--foo \r\nX-Mime: m2 header\r\n\r\nFrom: m2@example.com\r\nSubject: m2\r\n\r\nm2 body\r\n\r\n--foo--\r\n\r\nepilogue\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.header])", reply: "* 1 fetch (body[1.header] {128}\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\nContent-Type: multipart/digest; boundary=\"foo\"\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.text])", reply: "* 1 fetch (body[1.text] {168}\r\nprologue\r\n\r\n--foo \r\n\r\nFrom: m1@example.com\r\nSubject: m1\r\n\r\nm1 body\r\n\r\n--foo \r\nX-Mime: m2 header\r\n\r\nFrom: m2@example.com\r\nSubject: m2\r\n\r\nm2 body\r\n\r\n--foo--\r\n\r\nepilogue\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.1])", reply: "* 1 fetch (body[1.1] {46}\r\nFrom: m1@example.com\r\nSubject: m1\r\n\r\nm1 body\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.1.MIME])", reply: "* 1 fetch (body[1.1.MIME] {2}\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.1.HEADER])", reply: "* 1 fetch (body[1.1.HEADER] {37}\r\nFrom: m1@example.com\r\nSubject: m1\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.1.TEXT])", reply: "* 1 fetch (body[1.1.TEXT] {9}\r\nm1 body\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.2])", reply: "* 1 fetch (body[1.2] {46}\r\nFrom: m2@example.com\r\nSubject: m2\r\n\r\nm2 body\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.2.MIME])", reply: "* 1 fetch (body[1.2.MIME] {21}\r\nX-Mime: m2 header\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.2.HEADER])", reply: "* 1 fetch (body[1.2.HEADER] {37}\r\nFrom: m2@example.com\r\nSubject: m2\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.2.TEXT])", reply: "* 1 fetch (body[1.2.TEXT] {9}\r\nm2 body\r\n)\r\n"},
	}},
	{name: "fetch-body-message-rfc822-x2", steps: []portMIMEFetchStep{
		{command: "fetch 1 (body.peek[])", reply: "* 1 fetch (body[] {320}\r\nFrom: user@domain.org\r\nDate: Sat, 24 Mar 2007 23:00:00 +0200\r\nMime-Version: 1.0\r\nContent-Type: message/rfc822\r\n\r\nFrom: user2@domain.org\r\nDate: Fri, 23 Mar 2007 11:22:33 +0200\r\nMime-Version: 1.0\r\nContent-Type: message/rfc822\r\n\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\n\r\nHello world\r\n)\r\n"},
		{command: "fetch 1 (body.peek[text])", reply: "* 1 fetch (body[text] {207}\r\nFrom: user2@domain.org\r\nDate: Fri, 23 Mar 2007 11:22:33 +0200\r\nMime-Version: 1.0\r\nContent-Type: message/rfc822\r\n\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\n\r\nHello world\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1])", reply: "* 1 fetch (body[1] {207}\r\nFrom: user2@domain.org\r\nDate: Fri, 23 Mar 2007 11:22:33 +0200\r\nMime-Version: 1.0\r\nContent-Type: message/rfc822\r\n\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\n\r\nHello world\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.1])", reply: "* 1 fetch (body[1.1] {93}\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\n\r\nHello world\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.header])", reply: "* 1 fetch (body[1.header] {114}\r\nFrom: user2@domain.org\r\nDate: Fri, 23 Mar 2007 11:22:33 +0200\r\nMime-Version: 1.0\r\nContent-Type: message/rfc822\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.text])", reply: "* 1 fetch (body[1.text] {93}\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\n\r\nHello world\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.1.1])", reply: "* 1 fetch (body[1.1.1] {13}\r\nHello world\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.1.header])", reply: "* 1 fetch (body[1.1.header] {80}\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.1.text])", reply: "* 1 fetch (body[1.1.text] {13}\r\nHello world\r\n)\r\n"},
	}},
	{name: "fetch-body-mime", steps: []portMIMEFetchStep{
		{command: "fetch 1 (body.peek[])", reply: "* 1 fetch (body[] {602}\r\nFrom: user@domain.org\r\nDate: Sat, 24 Mar 2007 23:00:00 +0200\r\nMime-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"foo\r\n bar\"\r\n\r\nRoot MIME prologue\r\n\r\n--foo bar\r\nContent-Type: text/x-myown; charset=us-ascii\r\n\r\nhello\r\n\r\n--foo bar\r\nContent-Type: message/rfc822\r\n\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\nContent-Type: multipart/alternative; boundary=\"sub1\"\r\n\r\nSub MIME prologue\r\n--sub1\r\nContent-Type: text/html\r\n\r\n<p>Hello world</p>\r\n\r\n--sub1\r\nContent-Type: text/plain\r\n\r\nHello another world\r\n\r\n--sub1--\r\nSub MIME epilogue\r\n\r\n--foo bar--\r\nRoot MIME epilogue\r\n)\r\n"},
		{command: "fetch 1 (body.peek[text])", reply: "* 1 fetch (body[text] {466}\r\nRoot MIME prologue\r\n\r\n--foo bar\r\nContent-Type: text/x-myown; charset=us-ascii\r\n\r\nhello\r\n\r\n--foo bar\r\nContent-Type: message/rfc822\r\n\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\nContent-Type: multipart/alternative; boundary=\"sub1\"\r\n\r\nSub MIME prologue\r\n--sub1\r\nContent-Type: text/html\r\n\r\n<p>Hello world</p>\r\n\r\n--sub1\r\nContent-Type: text/plain\r\n\r\nHello another world\r\n\r\n--sub1--\r\nSub MIME epilogue\r\n\r\n--foo bar--\r\nRoot MIME epilogue\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1])", reply: "* 1 fetch (body[1] {7}\r\nhello\r\n)\r\n"},
		{command: "fetch 1 (body.peek[1.mime])", reply: "* 1 fetch (body[1.mime] {48}\r\nContent-Type: text/x-myown; charset=us-ascii\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[2])", reply: "* 1 fetch (body[2] {298}\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\nContent-Type: multipart/alternative; boundary=\"sub1\"\r\n\r\nSub MIME prologue\r\n--sub1\r\nContent-Type: text/html\r\n\r\n<p>Hello world</p>\r\n\r\n--sub1\r\nContent-Type: text/plain\r\n\r\nHello another world\r\n\r\n--sub1--\r\nSub MIME epilogue\r\n)\r\n"},
		{command: "fetch 1 (body.peek[2.mime])", reply: "* 1 fetch (body[2.mime] {32}\r\nContent-Type: message/rfc822\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[2.header])", reply: "* 1 fetch (body[2.header] {134}\r\nFrom: sub@domain.org\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nSubject: submsg\r\nContent-Type: multipart/alternative; boundary=\"sub1\"\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[2.header.fields (from subject X-foo)])", reply: "* 1 fetch (body[2.header.fields (from subject X-foo)] {41}\r\nFrom: sub@domain.org\r\nSubject: submsg\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[2.header.fields.not (from subject X-foo)])", reply: "* 1 fetch (body[2.header.fields.not (from subject X-foo)] {95}\r\nDate: Sun, 12 Aug 2012 12:34:56 +0300\r\nContent-Type: multipart/alternative; boundary=\"sub1\"\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[2.text])", reply: "* 1 fetch (body[2.text] {164}\r\nSub MIME prologue\r\n--sub1\r\nContent-Type: text/html\r\n\r\n<p>Hello world</p>\r\n\r\n--sub1\r\nContent-Type: text/plain\r\n\r\nHello another world\r\n\r\n--sub1--\r\nSub MIME epilogue\r\n)\r\n"},
		{command: "fetch 1 (body.peek[2.1.mime])", reply: "* 1 fetch (body[2.1.mime] {27}\r\nContent-Type: text/html\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[2.1])", reply: "* 1 fetch (body[2.1] {20}\r\n<p>Hello world</p>\r\n)\r\n"},
		{command: "fetch 1 (body.peek[2.2.mime])", reply: "* 1 fetch (body[2.2.mime] {28}\r\nContent-Type: text/plain\r\n\r\n)\r\n"},
		{command: "fetch 1 (body.peek[2.2])", reply: "* 1 fetch (body[2.2] {21}\r\nHello another world\r\n)\r\n"},
	}},
}

var portMIMEEnvelopes = []string{
	"(\"Thu, 15 Feb 2007 01:02:03 +0200\" \"subject header\" ((\"From Real\" NIL \"fromuser\" \"fromdomain.org\")) ((\"Sender Real\" NIL \"senderuser\" \"senderdomain.org\")) ((\"ReplyTo Real\" NIL \"replytouser\" \"replytodomain.org\")) ((\"To Real\" NIL \"touser\" \"todomain.org\")) ((\"Cc Real\" NIL \"ccuser\" \"ccdomain.org\")) ((\"Bcc Real\" NIL \"bccuser\" \"bccdomain.org\")) \"<reply@to.id>\" \"<msg@id>\")",
	"(\"Thu, 15 Feb 2007 01:02:03 +0200\" NIL ((NIL NIL \"user\" \"domain\")) ((NIL NIL \"user\" \"domain\")) ((NIL NIL \"user\" \"domain\")) NIL NIL NIL NIL NIL)",
	"(\"Thu, 15 Feb 2007 01:02:03 +0200\" NIL ((NIL NIL \"user\" \"domain\")) ((NIL NIL \"user\" \"domain\")) ((NIL NIL \"user\" \"domain\")) NIL NIL NIL NIL NIL)",
	"(\"Thu, 15 Feb 2007 01:02:03 +0200\" NIL ((\"Real Name\" NIL \"user\" \"domain\")) ((\"Real Name\" NIL \"user\" \"domain\")) ((\"Real Name\" NIL \"user\" \"domain\")) ((NIL NIL \"group\" NIL)(NIL NIL \"g1\" \"d1.org\")(NIL NIL \"g2\" \"d2.org\")(NIL NIL NIL NIL)(NIL NIL \"group2\" NIL)(NIL NIL \"g3\" \"d3.org\")(NIL NIL NIL NIL)) ((NIL NIL \"group\" NIL)(NIL NIL NIL NIL)(NIL NIL \"group2\" NIL)(NIL NIL NIL NIL)) NIL NIL NIL)",
	"(\"Thu, 15 Feb 2007 01:02:03 +0200\" NIL ((\"Real Name\" NIL \"user\" \"domain\")) ((\"Real Name\" NIL \"user\" \"domain\")) ((\"Real Name\" NIL \"user\" \"domain\")) NIL NIL NIL NIL NIL)",
	"(\"Thu, 15 Feb 2007 01:02:03 +0200\" NIL ((NIL \"@route\" \"user\" \"domain\")) ((NIL \"@route\" \"user\" \"domain\")) ((NIL \"@route\" \"user\" \"domain\")) NIL NIL NIL NIL NIL)",
}
