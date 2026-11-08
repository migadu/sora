package imapproxy

import (
	"bytes"
	"strconv"
)

// responseBoundary follows a server's IMAP response stream just far enough to tell when it
// stands between two responses: after the CRLF that ends a response line, outside any
// literal. That is the only place the proxy may put a response of its own (a BYE). A BYE
// written inside a literal is read as part of the message ("{20}" counts bytes, not
// lines), and one that completes a literal turns the rest of it into garbage.
//
// A data response or status response code can announce a literal with "{N}" (or "~{N}",
// literal8). Human-readable status and continuation text cannot. Literal bytes are
// skipped by count, never scanned, so a large FETCH costs nothing; only response lines
// are scanned, for their end.
type responseBoundary struct {
	literal int64           // literal bytes still to come
	inLine  bool            // inside a response line: some of it has been seen, not its end
	tail    []byte          // the last bytes of the current line, enough to find a "{N}" before its CRLF
	framing responseFraming // distinguishes literal-bearing syntax from human-readable text
}

// maxLiteralAnnouncement bounds the tail kept per line: "{" + 19 digits + "+}" + CRLF.
const maxLiteralAnnouncement = 24

// atBoundary reports whether the stream stands between two responses.
func (b *responseBoundary) atBoundary() bool {
	return b.literal == 0 && !b.inLine
}

// consume advances over p and returns how much of it was taken. With stopAtBoundary it
// stops right after the first point where the stream stands between responses (if any),
// so the caller can put something there; otherwise it takes all of p.
func (b *responseBoundary) consume(p []byte, stopAtBoundary bool) int {
	i := 0
	for i < len(p) {
		if b.literal > 0 {
			n := min(int64(len(p)-i), b.literal)
			b.literal -= n
			i += int(n)
			continue
		}
		end := bytes.IndexByte(p[i:], '\n')
		if end < 0 {
			b.keep(p[i:])
			b.inLine = true
			return len(p)
		}
		b.keep(p[i : i+end+1])
		i += end + 1
		if b.framing.canAnnounceLiteral() {
			if n, ok := literalAnnounced(b.tail); ok {
				b.literal = n
				b.tail = b.tail[:0]
				b.inLine = true // the response goes on after the literal
				continue
			}
		}
		b.tail = b.tail[:0]
		b.framing = responseFraming{}
		b.inLine = false
		if stopAtBoundary {
			return i
		}
	}
	return i
}

// keep records the response's framing and the line's last maxLiteralAnnouncement bytes.
func (b *responseBoundary) keep(p []byte) {
	b.framing.consume(p)
	if len(p) >= maxLiteralAnnouncement {
		b.tail = append(b.tail[:0], p[len(p)-maxLiteralAnnouncement:]...)
		return
	}
	b.tail = append(b.tail, p...)
	if over := len(b.tail) - maxLiteralAnnouncement; over > 0 {
		b.tail = append(b.tail[:0], b.tail[over:]...)
	}
}

type responsePhase uint8

const (
	responseStart responsePhase = iota
	responseMarker
	responseTag
	responseType
	responseStatusStart
	responseStatusCode
	responseText
	responseData
)

// responseFraming reads only the response header and optional status code. Its state
// survives split reads and literals; literal contents are never passed to consume.
// IMAP4rev1's BADCHARSET response code can contain literal strings, so only the text
// after the code is exempt from literal detection, not the entire status response.
type responseFraming struct {
	phase    responsePhase
	untagged bool
	typ      [len("PREAUTH")]byte
	typLen   int // capped at len(typ)+1: longer atoms cannot be a status type
	quoted   bool
	escaped  bool
}

func (f *responseFraming) canAnnounceLiteral() bool {
	return f.phase == responseData || (f.phase == responseStatusCode && !f.quoted)
}

func (f *responseFraming) consume(p []byte) {
	for _, c := range p {
		switch f.phase {
		case responseStart:
			switch c {
			case '*', '+':
				f.untagged = c == '*'
				f.phase = responseMarker
			default:
				f.phase = responseTag
			}
		case responseMarker:
			if c == ' ' {
				f.phase = responseStatusStart // '+' continuation
				if f.untagged {
					f.phase = responseType
				}
			}
		case responseTag:
			if c == ' ' {
				f.phase = responseType
			}
		case responseType:
			if c == ' ' {
				f.phase = responseData
				if !f.untagged || f.isStatusType() {
					f.phase = responseStatusStart
				}
			} else if f.typLen <= len(f.typ) {
				if f.typLen < len(f.typ) {
					f.typ[f.typLen] = c
				}
				f.typLen++
			}
		case responseStatusStart:
			f.phase = responseText
			if c == '[' {
				f.phase = responseStatusCode
			}
		case responseStatusCode:
			switch {
			case f.escaped:
				f.escaped = false
			case f.quoted && c == '\\':
				f.escaped = true
			case c == '"':
				f.quoted = !f.quoted
			case !f.quoted && c == ']':
				f.phase = responseText
			}
		case responseText, responseData:
			return
		}
	}
}

func (f *responseFraming) isStatusType() bool {
	if f.typLen > len(f.typ) {
		return false
	}
	typ := f.typ[:f.typLen]
	return bytes.EqualFold(typ, []byte("OK")) || bytes.EqualFold(typ, []byte("NO")) ||
		bytes.EqualFold(typ, []byte("BAD")) || bytes.EqualFold(typ, []byte("BYE")) ||
		bytes.EqualFold(typ, []byte("PREAUTH"))
}

// literalAnnounced reports whether a line (its tail, ending in LF) ends in "{N}" or
// "{N+}", and N.
func literalAnnounced(line []byte) (int64, bool) {
	line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
	if !bytes.HasSuffix(line, []byte("}")) {
		return 0, false
	}
	open := bytes.LastIndexByte(line, '{')
	if open < 0 {
		return 0, false
	}
	digits := bytes.TrimSuffix(line[open+1:len(line)-1], []byte("+"))
	if len(digits) == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(string(digits), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
