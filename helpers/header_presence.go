package helpers

import (
	"bufio"
	"bytes"
	"io"

	"github.com/emersion/go-message"
)

// HeaderPresenceBit identifies the fixed set of searchable fields recorded by
// migration70. A nil mask is unknown (legacy/old writer), not an absent header.
// Extending this set requires a new knownness/version representation: a clear
// bit in an existing non-nil mask may only describe these fields.
func HeaderPresenceBit(key string) (int16, bool) {
	switch key {
	case "from":
		return 1 << 0, true
	case "to":
		return 1 << 1, true
	case "cc":
		return 1 << 2, true
	case "bcc":
		return 1 << 3, true
	case "sender":
		return 1 << 4, true
	case "reply-to":
		return 1 << 5, true
	case "subject":
		return 1 << 6, true
	case "message-id":
		return 1 << 7, true
	case "in-reply-to":
		return 1 << 8, true
	case "references":
		return 1 << 9, true
	default:
		return 0, false
	}
}

// ExtractHeaderPresence records field existence, independent of whether its
// value is empty, a group, or an invalid address list. Call on the final headers
// that accompany stored bytes, including after Sieve edits. No old body is read.
func ExtractHeaderPresence(header message.Header) *int16 {
	var mask int16
	for _, key := range []string{"from", "to", "cc", "bcc", "sender", "reply-to", "subject", "message-id", "in-reply-to", "references"} {
		if header.Has(key) {
			bit, _ := HeaderPresenceBit(key)
			mask |= bit
		}
	}
	return &mask
}

// ExtractRawHeaderPresence scans the raw RFC 5322 header block up to the first
// empty line and records field existence for HeaderPresenceBit, tolerating
// malformed header lines that cause go-message's parser to fail on APPEND.
func ExtractRawHeaderPresence(raw []byte) *int16 {
	mask, _ := ExtractRawHeaderPresenceFromReader(bytes.NewReader(raw))
	return mask
}

// ExtractRawHeaderPresenceFromReader reads only the header block (stopping at
// the blank line separating headers from the body, or clean io.EOF) and returns
// the HeaderPresenceBit mask. If r returns a non-EOF error before the blank line,
// it returns nil and that error so callers never persist a truncated mask.
func ExtractRawHeaderPresenceFromReader(r io.Reader) (*int16, error) {
	br := bufio.NewReaderSize(r, 8192)
	var mask int16
	inLongLine := false

	for {
		slice, err := br.ReadSlice('\n')
		lineEnded := err != bufio.ErrBufferFull
		if err != nil && err != bufio.ErrBufferFull && err != io.EOF {
			return nil, err
		}

		if inLongLine {
			if lineEnded {
				inLongLine = false
			}
			if err == io.EOF {
				break
			}
			continue
		}

		if !lineEnded {
			inLongLine = true
			if len(slice) > 0 && slice[0] != ' ' && slice[0] != '\t' {
				if bit, ok := rawLineHeaderPresenceBit(slice); ok {
					mask |= bit
				}
			}
			continue
		}

		if len(slice) == 0 && err == io.EOF {
			break
		}

		line := slice
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			// Blank line terminates the RFC 5322 header block.
			break
		}
		if line[0] != ' ' && line[0] != '\t' {
			if bit, ok := rawLineHeaderPresenceBit(line); ok {
				mask |= bit
			}
		}
		if err == io.EOF {
			break
		}
	}

	return &mask, nil
}

func rawLineHeaderPresenceBit(line []byte) (int16, bool) {
	colon := bytes.IndexByte(line, ':')
	if colon <= 0 {
		return 0, false
	}
	name := line[:colon]
	for len(name) > 0 && (name[len(name)-1] == ' ' || name[len(name)-1] == '\t') {
		name = name[:len(name)-1]
	}
	if len(name) == 0 || len(name) > 32 {
		return 0, false
	}
	var lower [32]byte
	for i, c := range name {
		// RFC 5322 §3.6.8 ftext: printable US-ASCII except ':'.
		if c < 33 || c > 126 || c == ':' {
			return 0, false
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		lower[i] = c
	}
	return HeaderPresenceBit(string(lower[:len(name)]))
}
