package imaptest

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

const maxResponseBytes = 16 << 20

// Value is an IMAP atom, quoted string, literal, NIL, or nested parenthesized list.
// Literal text is kept as bytes in a Go string; it need not be UTF-8.
type Value struct {
	Text      string
	List      []Value
	IsList    bool
	IsNil     bool
	IsLiteral bool
}

func (v Value) String() string {
	if v.IsNil {
		return "NIL"
	}
	if v.IsList {
		parts := make([]string, len(v.List))
		for i, child := range v.List {
			parts[i] = child.String()
		}
		return "(" + strings.Join(parts, " ") + ")"
	}
	return v.Text
}

func (v Value) Uint() (uint64, error) {
	if v.IsList || v.IsNil || v.Text == "" {
		return 0, errors.New("expected an IMAP unsigned number")
	}
	for _, c := range v.Text {
		if c < '0' || c > '9' {
			return 0, errors.New("expected an IMAP unsigned number")
		}
	}
	n, err := strconv.ParseUint(v.Text, 10, 64)
	if err != nil {
		return 0, errors.New("IMAP unsigned number exceeds uint64")
	}
	return n, nil
}

// Reply excludes the leading '*', '+' or command tag from Values.
type Reply struct {
	Values []Value
	Status string
	Text   string
	code   []Value
	size   int
}

func (r Reply) Kind() string {
	if r.Status != "" {
		return r.Status
	}
	if len(r.Values) == 0 {
		return ""
	}
	if _, ok := r.Number(); ok && len(r.Values) > 1 {
		return strings.ToUpper(r.Values[1].Text)
	}
	return strings.ToUpper(r.Values[0].Text)
}

func (r Reply) Number() (uint64, bool) {
	if len(r.Values) == 0 {
		return 0, false
	}
	n, err := r.Values[0].Uint()
	return n, err == nil
}

// Response holds all untagged replies observed before a tagged completion.
type Response struct {
	Tag        string
	Status     string
	Text       string
	Untagged   []Reply
	Completion Reply
}

func (r Response) Data(kind string) []Reply {
	var out []Reply
	for _, reply := range r.Untagged {
		if strings.EqualFold(reply.Kind(), kind) {
			out = append(out, reply)
		}
	}
	return out
}

// Code returns the arguments of the first matching response code, or nil if
// absent. An existing argument-free code returns a non-nil empty slice.
func (r Response) Code(name string) []Value {
	if len(r.Completion.code) > 0 && strings.EqualFold(r.Completion.code[0].Text, name) {
		return r.Completion.code[1:]
	}
	for _, reply := range r.Untagged {
		if len(reply.code) > 0 && strings.EqualFold(reply.code[0].Text, name) {
			return reply.code[1:]
		}
	}
	return nil
}

func (r Response) Exists() (uint64, bool) {
	var n uint64
	found := false
	for _, reply := range r.Data("EXISTS") {
		n, found = reply.Number()
	}
	return n, found
}

func (r Response) Search() ([]uint64, error) {
	data := r.Data("SEARCH")
	if len(data) != 1 {
		return nil, &AssertionError{Message: fmt.Sprintf("expected one SEARCH response, got %d", len(data))}
	}
	var out []uint64
	for _, value := range data[0].Values[1:] {
		// SEARCH may carry a trailing MODSEQ extension list.
		if value.IsList {
			continue
		}
		n, err := value.Uint()
		if err != nil || n == 0 {
			return nil, errors.New("invalid message number in SEARCH response")
		}
		out = append(out, n)
	}
	return out, nil
}

type Fetch struct {
	Seq   uint64
	Attrs map[string]Value
}

func (r Response) Fetches() ([]Fetch, error) {
	var out []Fetch
	for _, reply := range r.Data("FETCH") {
		n, ok := reply.Number()
		if !ok || n == 0 || len(reply.Values) != 3 || !reply.Values[2].IsList {
			return nil, errors.New("malformed FETCH response")
		}
		values := reply.Values[2].List
		if len(values)%2 != 0 {
			return nil, errors.New("FETCH attributes are not key/value pairs")
		}
		fetch := Fetch{Seq: n, Attrs: make(map[string]Value)}
		for i := 0; i < len(values); i += 2 {
			key := values[i]
			if key.IsList || key.IsNil || key.Text == "" {
				return nil, errors.New("invalid FETCH attribute name")
			}
			fetch.Attrs[canonicalFetchAttribute(key.Text)] = values[i+1]
		}
		out = append(out, fetch)
	}
	return out, nil
}

// canonicalFetchAttribute normalizes the astring header field names in a body
// section. A server may quote these names even when the request used atoms, and
// their order and case do not change which header fields are selected.
func canonicalFetchAttribute(name string) string {
	upper := strings.ToUpper(name)
	fieldStart := strings.Index(upper, "HEADER.FIELDS")
	if fieldStart < 0 || !strings.HasPrefix(upper, "BODY[") {
		return upper
	}
	listStart := fieldStart + len("HEADER.FIELDS")
	if strings.HasPrefix(upper[listStart:], ".NOT") {
		listStart += len(".NOT")
	}
	for listStart < len(name) && (name[listStart] == ' ' || name[listStart] == '\t') {
		listStart++
	}
	if listStart >= len(name) || name[listStart] != '(' {
		return upper
	}
	p := valueParser{data: []byte(name[listStart:])}
	value, err := p.value(0)
	if err != nil || !value.IsList {
		return upper
	}
	fields := make([]string, 0, len(value.List))
	for _, field := range value.List {
		if field.IsList || field.Text == "" {
			return upper
		}
		fields = append(fields, strings.ToUpper(field.Text))
	}
	slices.Sort(fields)
	fields = slices.Compact(fields)
	for i, field := range fields {
		if strings.ContainsAny(field, " ()[]{}\"\\") {
			fields[i] = Quote(field)
		}
	}
	return strings.TrimRight(upper[:listStart], " \t") + " (" + strings.Join(fields, " ") + ")" + strings.TrimSpace(upper[listStart+p.pos:])
}

func (r Response) StatusValues(mailbox string) (map[string]uint64, error) {
	for _, reply := range r.Data("STATUS") {
		if len(reply.Values) != 3 || !reply.Values[2].IsList {
			return nil, errors.New("malformed STATUS response")
		}
		name := reply.Values[1].Text
		if name != mailbox && !(strings.EqualFold(mailbox, "INBOX") && strings.EqualFold(name, "INBOX")) {
			continue
		}
		values := reply.Values[2].List
		if len(values)%2 != 0 {
			return nil, errors.New("STATUS attributes are not key/value pairs")
		}
		out := make(map[string]uint64)
		for i := 0; i < len(values); i += 2 {
			n, err := values[i+1].Uint()
			if err != nil {
				return nil, err
			}
			out[strings.ToUpper(values[i].Text)] = n
		}
		return out, nil
	}
	return nil, &AssertionError{Message: "missing STATUS response for test mailbox"}
}

func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(part) > limit-len(line) {
			return nil, errors.New("IMAP response exceeds size limit")
		}
		line = append(line, part...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !bytes.HasSuffix(line, []byte("\r\n")) {
			return nil, errors.New("IMAP response does not end in CRLF")
		}
		return line, nil
	}
}

func isStatus(word string) bool {
	switch strings.ToUpper(word) {
	case "OK", "NO", "BAD", "BYE", "PREAUTH":
		return true
	}
	return false
}

// readReply first frames literal octets, then parses the complete logical reply.
// Status response text is opaque and may legally end in text such as "{123}".
func readReply(r *bufio.Reader) (string, Reply, error) {
	line, err := readLine(r, maxResponseBytes)
	if err != nil {
		return "", Reply{}, err
	}
	fields := strings.Fields(string(line))
	if len(fields) == 0 {
		return "", Reply{}, errors.New("empty IMAP response")
	}
	statusReply := fields[0] == "+" || (len(fields) > 1 && isStatus(fields[1]))
	raw := append([]byte(nil), line...)
	for !statusReply {
		n, literal, err := trailingLiteral(line)
		if err != nil {
			return "", Reply{}, err
		}
		if !literal {
			break
		}
		if n > maxResponseBytes-len(raw) {
			return "", Reply{}, errors.New("IMAP literal exceeds response size limit")
		}
		start := len(raw)
		raw = append(raw, make([]byte, n)...)
		if _, err := io.ReadFull(r, raw[start:]); err != nil {
			return "", Reply{}, err
		}
		line, err = readLine(r, maxResponseBytes-len(raw))
		if err != nil {
			return "", Reply{}, err
		}
		raw = append(raw, line...)
	}
	tag, reply, err := parseReply(raw)
	reply.size = len(raw)
	return tag, reply, err
}

func trailingLiteral(line []byte) (int, bool, error) {
	end := len(line) - 2 // CRLF
	if end < 3 || line[end-1] != '}' {
		return 0, false, nil
	}
	start := end - 2
	for start >= 0 && line[start] >= '0' && line[start] <= '9' {
		start--
	}
	if start < 0 || line[start] != '{' || start == end-2 {
		return 0, false, nil
	}
	n, err := strconv.ParseUint(string(line[start+1:end-1]), 10, 64)
	if err != nil || n > maxResponseBytes {
		return 0, false, errors.New("IMAP literal exceeds response size limit")
	}
	return int(n), true, nil
}

func parseReply(raw []byte) (string, Reply, error) {
	line := raw[:len(raw)-2]
	i := bytes.IndexByte(line, ' ')
	if i < 0 {
		if bytes.Equal(line, []byte("+")) {
			return "+", Reply{}, nil
		}
		return "", Reply{}, errors.New("missing IMAP response payload")
	}
	tag := string(line[:i])
	body := line[i+1:]
	if tag == "+" {
		return tag, Reply{Text: string(body)}, nil
	}
	word, rest, _ := bytes.Cut(body, []byte(" "))
	if isStatus(string(word)) {
		reply := Reply{Status: strings.ToUpper(string(word)), Values: []Value{{Text: strings.ToUpper(string(word))}}}
		if len(rest) > 0 && rest[0] == '[' {
			p := valueParser{data: rest, pos: 1}
			values, err := p.sequence(']', 0)
			if err != nil || len(values) == 0 {
				return "", Reply{}, errors.New("malformed IMAP response code")
			}
			reply.code = values
			reply.Values = append(reply.Values, Value{IsList: true, List: values})
			rest = rest[p.pos:]
		}
		reply.Text = strings.TrimLeft(string(rest), " ")
		return tag, reply, nil
	}
	if tag != "*" {
		return "", Reply{}, errors.New("invalid tagged IMAP completion")
	}
	p := valueParser{data: body}
	values, err := p.sequence(0, 0)
	if err != nil {
		return "", Reply{}, err
	}
	if len(values) == 0 {
		return "", Reply{}, errors.New("empty untagged IMAP response")
	}
	return tag, Reply{Values: values}, nil
}

type valueParser struct {
	data []byte
	pos  int
}

func (p *valueParser) sequence(end byte, depth int) ([]Value, error) {
	if depth > 64 {
		return nil, errors.New("IMAP response nesting exceeds limit")
	}
	values := make([]Value, 0)
	for p.pos < len(p.data) {
		if p.data[p.pos] == ' ' || p.data[p.pos] == '\t' {
			p.pos++
			continue
		}
		if end != 0 && p.data[p.pos] == end {
			p.pos++
			return values, nil
		}
		value, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if end != 0 {
		return nil, errors.New("unterminated IMAP list or response code")
	}
	return values, nil
}

func (p *valueParser) value(depth int) (Value, error) {
	start := p.pos
	switch p.data[p.pos] {
	case '(':
		p.pos++
		values, err := p.sequence(')', depth+1)
		return Value{List: values, IsList: true}, err
	case ')', ']', '\r', '\n':
		return Value{}, errors.New("unexpected delimiter in IMAP response")
	case '"':
		p.pos++
		var text []byte
		for p.pos < len(p.data) {
			c := p.data[p.pos]
			p.pos++
			if c == '"' {
				return Value{Text: string(text)}, nil
			}
			if c == '\\' {
				if p.pos >= len(p.data) || (p.data[p.pos] != '\\' && p.data[p.pos] != '"') {
					return Value{}, errors.New("invalid quoted IMAP string escape")
				}
				c = p.data[p.pos]
				p.pos++
			}
			if c == '\r' || c == '\n' || c == 0 {
				return Value{}, errors.New("invalid control byte in quoted IMAP string")
			}
			text = append(text, c)
		}
		return Value{}, errors.New("unterminated quoted IMAP string")
	}
	if p.data[p.pos] == '{' || (p.data[p.pos] == '~' && p.pos+1 < len(p.data) && p.data[p.pos+1] == '{') {
		if p.data[p.pos] == '~' {
			p.pos++
		}
		p.pos++
		digits := p.pos
		for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
			p.pos++
		}
		if p.pos == digits || p.pos+2 >= len(p.data) || !bytes.Equal(p.data[p.pos:p.pos+3], []byte("}\r\n")) {
			return Value{}, errors.New("invalid IMAP literal marker")
		}
		n, err := strconv.ParseUint(string(p.data[digits:p.pos]), 10, 64)
		p.pos += 3
		if err != nil || n > uint64(len(p.data)-p.pos) {
			return Value{}, errors.New("truncated IMAP literal")
		}
		text := string(p.data[p.pos : p.pos+int(n)])
		p.pos += int(n)
		return Value{Text: text, IsLiteral: true}, nil
	}
	brackets := 0
	quoted := false
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		if brackets > 0 && quoted {
			p.pos++
			if c == '\\' {
				if p.pos >= len(p.data) || (p.data[p.pos] != '"' && p.data[p.pos] != '\\') {
					return Value{}, errors.New("invalid quoted section string escape")
				}
				p.pos++
			} else if c == '"' {
				quoted = false
			} else if c == '\r' || c == '\n' || c == 0 {
				return Value{}, errors.New("invalid control byte in quoted section string")
			}
			continue
		}
		if brackets == 0 && (c == ' ' || c == '\t' || c == '(' || c == ')' || c == ']' || c == '\r' || c == '\n') {
			break
		}
		if brackets > 0 && c == '"' {
			quoted = true
		} else if c == '[' {
			brackets++
		} else if c == ']' {
			brackets--
		}
		p.pos++
	}
	if p.pos == start || brackets != 0 || quoted {
		return Value{}, errors.New("invalid atom or section in IMAP response")
	}
	text := string(p.data[start:p.pos])
	return Value{Text: text, IsNil: strings.EqualFold(text, "NIL")}, nil
}
